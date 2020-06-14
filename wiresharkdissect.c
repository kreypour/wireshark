/* wiresharkdissect.c
 *
 * wiresharkdissect.dll Library
 * Exporting a simple function to enable usage of the dissectors from C# on Windows.
 * 
 * Author: Kam Reypour
 */

#include "wiresharkdissect.h"
#include <stdio.h>
#include <wiretap/wtap.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <cfile.h>
#include "frame_tvbuff.h"
#include <epan/print_stream.h>
#include <epan/print.h>
#include <windows.h>
#include <fcntl.h>

static FILE *win32_fmemopen();
static const nstime_t *get_frame_ts(struct packet_provider_data *prov, guint32 frame_num);
static void failure_warning_message(const char *msg_format, va_list ap);
static void open_failure_message(const char *filename, int err,
                                 gboolean for_writing);
static void read_failure_message(const char *filename, int err);
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);

static proto_node_children_grouper_func node_children_grouper = 
         proto_node_group_children_by_unique;
struct epan_session *epan;
static gboolean init = FALSE;

int dissect(const char *input, int input_len, char *output, int output_len, gboolean detailed_json)
{
   int ret                          = 1;
   wtap_rec *rec                    = NULL;
   Buffer *buf                      = NULL;
   epan_dissect_t *edt              = NULL;
   frame_data *fdata                = NULL;
   output_fields_t *output_fields   = NULL;
   FILE *mstream                    = NULL;

   if (!init)
   {
      wtap_init(FALSE);

      if (!epan_init(NULL, NULL, FALSE))
      {
         ret = 10;
         goto CLEANUP;
      }

      init_report_message(
         failure_warning_message,
         failure_warning_message,
         open_failure_message,
         read_failure_message,
         write_failure_message
      );

      static const struct packet_provider_funcs funcs = {
         get_frame_ts,
         epan_get_interface_name,
         epan_get_interface_description,
         NULL
      };
      epan = epan_new(NULL, &funcs);

      init = TRUE;
   }

   // rec will contain information about the input frame
   rec = malloc(sizeof(wtap_rec));
   wtap_rec_init(rec);
   rec->rec_type = REC_TYPE_PACKET;
   rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;
   rec->rec_header.packet_header.caplen = input_len;
   rec->rec_header.packet_header.len = input_len;
   rec->presence_flags = 0;

   // this is the buffer that epan dissect takes as input
   buf = malloc(sizeof(Buffer));
   ws_buffer_init(buf, input_len);
   memcpy(buf->data, input, input_len);

   // edt is the structure where we give the input and receive our dissected frame
   edt = epan_dissect_new(epan, TRUE, TRUE);

   // frame data
   fdata = malloc(sizeof(frame_data));
   frame_data_init(fdata, 1, rec, 0, 0);

   // capture file which we don't have
   capture_file cf;
   memset(&cf, 0, sizeof(capture_file));
   cf.provider.ref = fdata;
   cf.count = 1;

   // pre processing
   prime_epan_dissect_with_postdissector_wanted_hfids(&edt);

   // pre processing
   frame_data_set_before_dissect(
      fdata, 
      &cf.elapsed_time,
      &cf.provider.ref,
      cf.provider.prev_dis
   );

   // this is where the actual dissection happens the results are in edt
   epan_dissect_run_with_taps(
      edt,
      WTAP_ENCAP_ETHERNET,
      rec,
      frame_tvbuff_new_buffer(&cf.provider, fdata, buf),
      fdata,
      NULL
   );

   output_fields = output_fields_new();

   // to convert the results to JSON we will need a stream to provide to
   // write_json_proto_tree, normally either a file or STDOUT is given
   // however, we need receive the out put as a string to give back to caller
   // mstream is a memory file stream that will get the job done
   mstream = win32_fmemopen();
   if (mstream == NULL)
   {
      ret = 20;
      goto CLEANUP;
   }

   if (detailed_json)
   {
      json_dumper jdumper = {
         .output_file = mstream
      };
      pf_flags protocolfilter_flags = PF_NONE;

      // generate the JSON output and put it in mstream
      write_json_proto_tree(
         output_fields,
         print_dissections_expanded,
         0,
         NULL,
         protocolfilter_flags,
         edt,
         NULL,
         node_children_grouper,
         &jdumper
      );
   }
   else
   {
      print_stream_t *print_stream = print_stream_text_stdio_new(mstream);
      if (!proto_tree_print(TRUE, TRUE, edt, FALSE, print_stream))
      {
         ret = 30;
         goto CLEANUP;
      }
   }

   // get the size of the generated output and make sure it fits
   size_t mstream_len = ftell(mstream);
   if (mstream_len > output_len)
   {
      ret = ERROR_INSUFFICIENT_BUFFER;
      goto CLEANUP;
   }

   // go to the beginning of mstream and read the JSON object
   rewind(mstream);
   size_t read_len = fread(output, sizeof(char), mstream_len, mstream);
   // per MSDN: "we recommend you null-terminate character data at 
   // buffer[return_value * size] if the intent of the buffer is to 
   // act as a C-style string."
   output[read_len * sizeof(char)] = '\0';
   ret = 0;

CLEANUP:
   if (mstream != NULL)
   {
      fclose(mstream);
      mstream = NULL;
   }

   postseq_cleanup_all_protocols();

   if (edt != NULL)
   {
      epan_dissect_free(edt);
      edt = NULL;
   }

   if (buf != NULL)
   {
      ws_buffer_free(buf);
      free(buf);
      buf = NULL;
   }

   if (rec != NULL)
   {
      wtap_rec_cleanup(rec);
      free(rec);
      rec = NULL;
   }

   if (fdata != NULL)
   {
      frame_data_destroy(fdata);
      free(fdata);
      fdata = NULL;
   }

   if (output_fields != NULL)
   {
      output_fields_free(output_fields);
      output_fields = NULL;
   }

   wtap_cleanup();

   return ret;
}

static FILE *
win32_fmemopen()
{
   // since there is no fmemopen in Windows, based on Larry Osterman's "temporary temporary files":
   // https://docs.microsoft.com/en-us/archive/blogs/larryosterman/its-only-temporary
   // we will get a FILE handle which won't write to disk unless we run out of physical memory
   FILE *ret = NULL;
   char tempPath[MAX_PATH];

   if (GetTempPath(MAX_PATH, tempPath))
   {
      char tempFileName[MAX_PATH];

      if (GetTempFileName(tempPath, "", 0, tempFileName))
      {
         HANDLE h = CreateFile(
            tempFileName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            0,
            OPEN_ALWAYS, 
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
            0
         );
         if (h != INVALID_HANDLE_VALUE)
         {
            int fd = _open_osfhandle((intptr_t)h, _O_RDWR);
            if (fd != -1)
            {
               ret = _fdopen(fd, "w+");
            }
         }
      }
   }

   return ret;
}

static const nstime_t *
get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
   if (prov->ref && prov->ref->num == frame_num)
      return &prov->ref->abs_ts;

   if (prov->prev_dis && prov->prev_dis->num == frame_num)
      return &prov->prev_dis->abs_ts;

   if (prov->prev_cap && prov->prev_cap->num == frame_num)
      return &prov->prev_cap->abs_ts;

   if (prov->frames)
   {
      frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

      return (fd) ? &fd->abs_ts : NULL;
   }

   return NULL;
}

static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
   // no op
}

static void
read_failure_message(const char *filename, int err)
{
   // no op
}

static void
write_failure_message(const char *filename, int err)
{
   // no op
}

static void
failure_message_cont(const char *msg_format, va_list ap)
{
   // no op
}

static void
failure_warning_message(const char *msg_format, va_list ap)
{
   // no op
}
