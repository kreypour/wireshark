#include "wiresharkdissectors.h"
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

struct epan_session *epan;
static gboolean init = FALSE;

int dissect(const char *input, int input_len, char *output, int output_len)
{
   if (!init)
   {
      wtap_init(FALSE);
      if (!epan_init(NULL, NULL, FALSE))
      {
         return (10);
      }
      init_report_message(failure_warning_message, failure_warning_message,
                          open_failure_message, read_failure_message,
                          write_failure_message);

      static const struct packet_provider_funcs funcs = {
          get_frame_ts,
          epan_get_interface_name,
          epan_get_interface_description,
          NULL};
      epan = epan_new(NULL, &funcs);

      init = TRUE;
   }

   wtap_rec rec;
   wtap_rec_init(&rec);
   rec.rec_type = REC_TYPE_PACKET;
   rec.rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;
   rec.rec_header.packet_header.caplen = input_len;
   rec.rec_header.packet_header.len = input_len;
   rec.presence_flags = 0;

   Buffer buf;
   ws_buffer_init(&buf, input_len);
   memcpy(buf.data, input, input_len);

   epan_dissect_t *edt = NULL;
   edt = epan_dissect_new(epan, TRUE, TRUE);

   frame_data fdata;
   frame_data_init(&fdata, 1, &rec, 0, 0);

   capture_file cf;
   memset(&cf, 0, sizeof(capture_file));
   cf.provider.ref = &fdata;
   cf.provider.prev_dis = NULL;
   cf.provider.prev_cap = NULL;
   cf.count = 1;

   prime_epan_dissect_with_postdissector_wanted_hfids(&edt);
   frame_data_set_before_dissect(&fdata, &cf.elapsed_time,
                                 &cf.provider.ref, cf.provider.prev_dis);

   epan_dissect_run_with_taps(edt, WTAP_ENCAP_ETHERNET, &rec,
                              frame_tvbuff_new_buffer(&cf.provider, &fdata, &buf),
                              &fdata, NULL);

   output_fields_t *output_fields = NULL;
   output_fields = output_fields_new();

   static proto_node_children_grouper_func node_children_grouper = proto_node_group_children_by_unique;
   FILE *mstream = win32_fmemopen();
   if (mstream == NULL)
   {
      return (20);
   }
   json_dumper jdumper = {
       .output_file = mstream};
   pf_flags protocolfilter_flags = PF_NONE;
   write_json_proto_tree(output_fields, print_dissections_expanded,
                         0, NULL, protocolfilter_flags,
                         edt, NULL, node_children_grouper, &jdumper);
   size_t mstream_len = ftell(mstream);
   rewind(mstream);
   if (mstream_len < output_len)
   {
      size_t read_len = fread(output, sizeof(char), mstream_len, mstream);
      output[read_len * sizeof(char)] = '\0';
   }
   else
   {
      return (30);
   }

   epan_dissect_free(edt);
   postseq_cleanup_all_protocols();
   ws_buffer_free(&buf);
   wtap_rec_cleanup(&rec);
   frame_data_destroy(&fdata);
   output_fields_free(output_fields);

   fclose(mstream);

   wtap_cleanup();
   free_progdirs();

   return 0;
}

static FILE *
win32_fmemopen()
{
   // Since there is no fmemopen in Windows, based on Larry Osterman's "temporary temporary files":
   // https://docs.microsoft.com/en-us/archive/blogs/larryosterman/its-only-temporary
   // we will get a FILE handle which won't write to disk unless we run out of physical memory
   FILE *ret = NULL;
   char tempPath[MAX_PATH];
   if (GetTempPath(MAX_PATH, tempPath))
   {
      char tempFileName[MAX_PATH];
      if (GetTempFileName(tempPath, "", 0, tempFileName))
      {
         HANDLE h = CreateFile(tempFileName, GENERIC_READ | GENERIC_WRITE, 0, 0,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, 0);
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
