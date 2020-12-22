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
#include <wsutil/utf8_entities.h>

char* print_columns(column_info* cinfo, const epan_dissect_t* edt);
static FILE *win32_fmemopen();
static const nstime_t *get_frame_ts(struct packet_provider_data *prov, guint32 frame_num);
static void failure_warning_message(const char *msg_format, va_list ap);
static void open_failure_message(const char *filename, int err,
                                 gboolean for_writing);
static void read_failure_message(const char *filename, int err);
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);

static gchar* delimiter_char = " ";

static proto_node_children_grouper_func node_children_grouper = 
         proto_node_group_children_by_unique;
struct epan_session *epan;
static gboolean init = FALSE;

int dissect(
   const char *input,
   int input_len,
   char *output,
   int output_len,
   gboolean detailed_json,
   int pkt_size,
   int encap_type,
   guint64 timestamp)
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
   rec->rec_header.packet_header.pkt_encap = encap_type;
   rec->rec_header.packet_header.caplen = input_len;
   rec->rec_header.packet_header.len = pkt_size;
   rec->ts.secs = timestamp / 1000000000;
   rec->ts.nsecs = timestamp % 1000000000;
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

   column_info cinfo;
   build_column_format_array(&cinfo, 8, TRUE);
   // this is where the actual dissection happens the results are in edt
    epan_dissect_run_with_taps(
       edt,
       encap_type, // found in wtap.h, i.e. WTAP_ENCAP_ETHERNET
       rec,
       frame_tvbuff_new_buffer(&cf.provider, fdata, buf),
       fdata,
       &cinfo
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
   }
   else
   {
      epan_dissect_fill_in_columns(edt, FALSE, TRUE);
      char *line = print_columns(&cinfo, edt);
      int line_len = strlen(line);
      if (output_len < line_len)
      {
         ret = ERROR_INSUFFICIENT_BUFFER;
         goto CLEANUP;
      }
      strcpy(output, line);
   }

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

static char *
get_line_buf(char* line_bufp, size_t len)
{
   static size_t line_buf_len = 512;
   size_t new_line_buf_len;

   for (new_line_buf_len = line_buf_len; len > new_line_buf_len;
        new_line_buf_len *= 2)
      ;
   if (line_bufp == NULL)
   {
      line_buf_len = new_line_buf_len;
      line_bufp = (char *)g_malloc(line_buf_len + 1);
   }
   else
   {
      if (new_line_buf_len > line_buf_len)
      {
         line_buf_len = new_line_buf_len;
         line_bufp = (char *)g_realloc(line_bufp, line_buf_len + 1);
      }
   }
   return line_bufp;
}

static inline void
put_string(char *dest, const char *str, size_t str_len)
{
   memcpy(dest, str, str_len);
   dest[str_len] = '\0';
}

static inline void
put_spaces_string(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
   size_t i;

   for (i = str_len; i < str_with_spaces; i++)
      *dest++ = ' ';

   put_string(dest, str, str_len);
}

static inline void
put_string_spaces(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
   size_t i;

   memcpy(dest, str, str_len);
   for (i = str_len; i < str_with_spaces; i++)
      dest[i] = ' ';

   dest[str_with_spaces] = '\0';
}

static void
json_puts_string(char* json_bufp, size_t* json_offset, char* str)
{
    if (!str) {
        json_bufp = get_line_buf(json_bufp, *json_offset + 1);
        strncpy(json_bufp + *json_offset, '"', 1);
        *json_offset += 1;

        // Maybe add "N/A" or something here later

        json_bufp = get_line_buf(json_bufp, *json_offset + 1);
        strncpy(json_bufp + *json_offset, '"', 1);
        *json_offset += 1;
        return;
    }

    static const char json_cntrl[0x20][6] = {
        "u0000", "u0001", "u0002", "u0003", "u0004", "u0005", "u0006", "u0007", "b",     "t",     "n",     "u000b", "f",     "r",     "u000e", "u000f",
        "u0010", "u0011", "u0012", "u0013", "u0014", "u0015", "u0016", "u0017", "u0018", "u0019", "u001a", "u001b", "u001c", "u001d", "u001e", "u001f"
    };

    json_bufp = get_line_buf(json_bufp, *json_offset + 1);
    strncpy(json_bufp + *json_offset, "\"", 1);
    *json_offset += 1;
    for (int i = 0; str[i]; i++) {
        if ((guint)str[i] < 0x20) {
            json_bufp = get_line_buf(json_bufp, *json_offset + 1);
            strncpy(json_bufp + *json_offset, '\\', 1);
            *json_offset += 1;
            json_bufp = get_line_buf(json_bufp, *json_offset + 1);
            strncpy(json_bufp + *json_offset, json_cntrl[(guint)str[i]], 1);
            *json_offset += 1;
        } else if (i > 0 && str[i - 1] == '<' && str[i] == '/') {
            // Convert </script> to <\/script> to avoid breaking web pages.
            json_bufp = get_line_buf(json_bufp, *json_offset + 1);
            strncpy(json_bufp + *json_offset, "/", 1);
            *json_offset += 1;
        } else {
            if (str[i] == '\\' || str[i] == '"') {
                json_bufp = get_line_buf(json_bufp, *json_offset + 1);
                strncpy(json_bufp + *json_offset, "\\", 1);
                *json_offset += 1;
            }
            json_bufp = get_line_buf(json_bufp, *json_offset + 1);
            strncpy(json_bufp + *json_offset, &str[i], 1);
            *json_offset += 1;
        }
    }
    json_bufp = get_line_buf(json_bufp, *json_offset + 1);
    strncpy(json_bufp + *json_offset, "\"", 1);
    *json_offset += 1;
}

static inline void
add_json_entry(char* json_bufp, size_t* json_offset, char* name, char* value, BOOL comma_prefix)
{
    size_t len = comma_prefix ?
        *json_offset + strlen(name) + strlen(value) + 3:
        *json_offset + strlen(name) + strlen(value) + 2;

    json_bufp = get_line_buf(json_bufp, len);

    if (comma_prefix)
    {
        strncpy(json_bufp + *json_offset, ",", 1);
        *json_offset += 1;
    }

    strncpy(json_bufp + *json_offset, name, strlen(name));
    *json_offset += strlen(name);
    json_puts_string(json_bufp, json_offset, value);
}

// this is tshark's print_columns with some modifications
char *print_columns(column_info *cinfo, const epan_dissect_t *edt)
{
   static gchar* json_smry_prop = "\"summary\":";
   static gchar* json_src_prop = "\"src_addr\":";
   static gchar* json_dst_prop = "\"dst_addr\":";
   static gchar* json_proto_prop = "\"protocol\":";

   static char* json_bufp = NULL;
   static char* smry_bufp = NULL;
   static char* src_bufp = NULL;
   static char* dst_bufp = NULL;
   static char* proto_bufp = NULL;
   
   int i;
   size_t json_offset;
   size_t buf_offset;
   size_t column_len;
   size_t col_len;
   col_item_t *col_item;
   gchar str_format[11];

   json_offset = 0;
   buf_offset = 0;
   json_bufp = get_line_buf(json_bufp, 512);
   *json_bufp = '\0';
   smry_bufp = get_line_buf(smry_bufp, 512);
   *smry_bufp = '\0';
   src_bufp = get_line_buf(src_bufp, 512);
   *src_bufp = '\0';
   dst_bufp = get_line_buf(dst_bufp, 512);
   *dst_bufp = '\0';
   proto_bufp = get_line_buf(proto_bufp, 512);
   *proto_bufp = '\0';

   for (i = 0; i < cinfo->num_cols; i++)
   {
      col_item = &cinfo->columns[i];
      /* Skip columns not marked as visible. */
      if (!get_column_visible(i))
         continue;
      switch (col_item->col_fmt)
      {
      case COL_NUMBER:
         // we don't need a column number
         continue;

      case COL_CLS_TIME:
      case COL_REL_TIME:
      case COL_ABS_TIME:
      case COL_ABS_YMD_TIME:  /* XXX - wider */
      case COL_ABS_YDOY_TIME: /* XXX - wider */
      case COL_UTC_TIME:
      case COL_UTC_YMD_TIME:  /* XXX - wider */
      case COL_UTC_YDOY_TIME: /* XXX - wider */
         // we don't need time info
         continue;

      case COL_DEF_SRC:
      case COL_RES_SRC:
      case COL_UNRES_SRC:
      case COL_DEF_DL_SRC:
      case COL_RES_DL_SRC:
      case COL_UNRES_DL_SRC:
      case COL_DEF_NET_SRC:
      case COL_RES_NET_SRC:
      case COL_UNRES_NET_SRC:
         column_len = col_len = strlen(col_item->col_data);
         if (column_len < 12)
            column_len = 12;
         smry_bufp = get_line_buf(smry_bufp, buf_offset + column_len);
         put_spaces_string(smry_bufp + buf_offset, col_item->col_data, col_len, column_len);
         src_bufp = get_line_buf(src_bufp, buf_offset + column_len);
         put_string(src_bufp, col_item->col_data, column_len);
         break;

      case COL_DEF_DST:
      case COL_RES_DST:
      case COL_UNRES_DST:
      case COL_DEF_DL_DST:
      case COL_RES_DL_DST:
      case COL_UNRES_DL_DST:
      case COL_DEF_NET_DST:
      case COL_RES_NET_DST:
      case COL_UNRES_NET_DST:
         column_len = col_len = strlen(col_item->col_data);
         if (column_len < 12)
            column_len = 12;
         smry_bufp = get_line_buf(smry_bufp, buf_offset + column_len);
         put_string_spaces(smry_bufp + buf_offset, col_item->col_data, col_len, column_len);
         dst_bufp = get_line_buf(dst_bufp, buf_offset + column_len);
         put_string(dst_bufp, col_item->col_data, column_len);
         break;

      case COL_PROTOCOL:
          proto_bufp = get_line_buf(proto_bufp, buf_offset + column_len);
          put_string(proto_bufp, col_item->col_data, column_len);
          /* FALLTHROUGH */

      default:
         column_len = strlen(col_item->col_data);
         smry_bufp = get_line_buf(smry_bufp, buf_offset + column_len);
         put_string(smry_bufp + buf_offset, col_item->col_data, column_len);
         break;
      }
      buf_offset += column_len;
      if (i != cinfo->num_cols - 1)
      {
         /*
       * This isn't the last column, so we need to print a
       * separator between this column and the next.
       *
       * If we printed a network source and are printing a
       * network destination of the same type next, separate
       * them with a UTF-8 right arrow; if we printed a network
       * destination and are printing a network source of the same
       * type next, separate them with a UTF-8 left arrow;
       * otherwise separate them with a space.
       *
       * We add enough space to the buffer for " \xe2\x86\x90 "
       * or " \xe2\x86\x92 ", even if we're only adding " ".
       */
         smry_bufp = get_line_buf(smry_bufp, buf_offset + 5);
         switch (col_item->col_fmt)
         {

         case COL_DEF_SRC:
         case COL_RES_SRC:
         case COL_UNRES_SRC:
            switch (cinfo->columns[i + 1].col_fmt)
            {

            case COL_DEF_DST:
            case COL_RES_DST:
            case COL_UNRES_DST:
               g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
               put_string(smry_bufp + buf_offset, str_format, 5);
               buf_offset += 5;
               break;

            default:
               put_string(smry_bufp + buf_offset, delimiter_char, 1);
               buf_offset += 1;
               break;
            }
            break;

         case COL_DEF_DL_SRC:
         case COL_RES_DL_SRC:
         case COL_UNRES_DL_SRC:
            switch (cinfo->columns[i + 1].col_fmt)
            {

            case COL_DEF_DL_DST:
            case COL_RES_DL_DST:
            case COL_UNRES_DL_DST:
               g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
               put_string(smry_bufp + buf_offset, str_format, 5);
               buf_offset += 5;
               break;

            default:
               put_string(smry_bufp + buf_offset, delimiter_char, 1);
               buf_offset += 1;
               break;
            }
            break;

         case COL_DEF_NET_SRC:
         case COL_RES_NET_SRC:
         case COL_UNRES_NET_SRC:
            switch (cinfo->columns[i + 1].col_fmt)
            {

            case COL_DEF_NET_DST:
            case COL_RES_NET_DST:
            case COL_UNRES_NET_DST:
               g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
               put_string(smry_bufp + buf_offset, str_format, 5);
               buf_offset += 5;
               break;

            default:
               put_string(smry_bufp + buf_offset, delimiter_char, 1);
               buf_offset += 1;
               break;
            }
            break;

         case COL_DEF_DST:
         case COL_RES_DST:
         case COL_UNRES_DST:
            switch (cinfo->columns[i + 1].col_fmt)
            {

            case COL_DEF_SRC:
            case COL_RES_SRC:
            case COL_UNRES_SRC:
               g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
               put_string(smry_bufp + buf_offset, str_format, 5);
               buf_offset += 5;
               break;

            default:
               put_string(smry_bufp + buf_offset, delimiter_char, 1);
               buf_offset += 1;
               break;
            }
            break;

         case COL_DEF_DL_DST:
         case COL_RES_DL_DST:
         case COL_UNRES_DL_DST:
            switch (cinfo->columns[i + 1].col_fmt)
            {

            case COL_DEF_DL_SRC:
            case COL_RES_DL_SRC:
            case COL_UNRES_DL_SRC:
               g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
               put_string(smry_bufp + buf_offset, str_format, 5);
               buf_offset += 5;
               break;

            default:
               put_string(smry_bufp + buf_offset, delimiter_char, 1);
               buf_offset += 1;
               break;
            }
            break;

         case COL_DEF_NET_DST:
         case COL_RES_NET_DST:
         case COL_UNRES_NET_DST:
            switch (cinfo->columns[i + 1].col_fmt)
            {

            case COL_DEF_NET_SRC:
            case COL_RES_NET_SRC:
            case COL_UNRES_NET_SRC:
               g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
               put_string(smry_bufp + buf_offset, str_format, 5);
               buf_offset += 5;
               break;

            default:
               put_string(smry_bufp + buf_offset, delimiter_char, 1);
               buf_offset += 1;
               break;
            }
            break;

         default:
            put_string(smry_bufp + buf_offset, delimiter_char, 1);
            buf_offset += 1;
            break;
         }
      }
   }

   // build the response json
   json_bufp = get_line_buf(json_bufp, json_offset + 1);
   strncpy(json_bufp + json_offset, "{", 1);
   json_offset += 1;

   if (strlen(smry_bufp) != 0)
   {
       add_json_entry(json_bufp, &json_offset, json_smry_prop, smry_bufp, FALSE);
   }
   if (strlen(src_bufp) != 0)
   {
       add_json_entry(json_bufp, &json_offset, json_src_prop, src_bufp, TRUE);
   }
   if (strlen(dst_bufp) != 0)
   {
       add_json_entry(json_bufp, &json_offset, json_dst_prop, dst_bufp, TRUE);
   }
   if (strlen(proto_bufp) != 0)
   {
       add_json_entry(json_bufp, &json_offset, json_proto_prop, proto_bufp, TRUE);
   }

   json_bufp = get_line_buf(json_bufp, json_offset + 2);
   strncpy(json_bufp + json_offset, "}\0", 2);

   return json_bufp;
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
