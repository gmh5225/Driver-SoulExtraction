#include <stdlib.h>
#include <intrin.h>

#include "Lib.SoulExtraction.h"
extern "C" {
#include "linux\verify_pefile.h"
}

__forceinline size_t
_strlen_a(const char *s)
{
    char *s0 = (char *)s;

    if (s == 0)
        return 0;

    while (*s != 0)
        s++;

    return (s - s0);
}

__forceinline size_t
_strlen_w(const wchar_t *s)
{
    wchar_t *s0 = (wchar_t *)s;

    if (s == 0)
        return 0;

    while (*s != 0)
        s++;

    return (s - s0);
}

__forceinline size_t
ultostr_a(unsigned long x, char *s)
{
    unsigned long t = x;
    size_t i, r = 1;

    while (t >= 10)
    {
        t /= 10;
        r++;
    }

    if (s == 0)
        return r;

    for (i = r; i != 0; i--)
    {
        s[i - 1] = (char)(x % 10) + '0';
        x /= 10;
    }

    s[r] = (char)0;
    return r;
}

__forceinline char *
_strcat_a(char *dest, const char *src)
{
    if ((dest == 0) || (src == 0))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0)
    {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}

__forceinline int
_isdigit_w(wchar_t x)
{
    return ((x >= L'0') && (x <= L'9'));
}

__forceinline unsigned long long
strtou64_a(char *s)
{
    unsigned long long a = 0;
    char c;

    if (s == 0)
        return 0;

    while (*s != 0)
    {
        c = *s;
        if (_isdigit_w(c))
            a = (a * 10) + (c - '0');
        else
            break;
        s++;
    }
    return a;
}

namespace LibSoulExtraction {

#define SIGN_NOT_3RDPARTY_TAG (19)   // Non-third-party tag is 19. May not be correct
#define SIGN_MAIN_SIG_AKID_SIZE (24) // The size of the main signature is usually 24. It may not be right

static bool
IsUTF8(char *Buffer, unsigned long Size, bool ExcludeAscii /*= true*/)
{
    bool b_utf8 = true;
    bool b_ascii = true;

    unsigned char *start = (unsigned char *)Buffer;
    unsigned char *end = (unsigned char *)Buffer + Size;

    while (start < end)
    {
        if ((*start & 0x80) != 0)
        {
            b_ascii = false;
        }

        if (*start < 0x80)
        {
            start += 1;
        }
        else if (*start < (0xC0))
        {
            b_utf8 = false;

            break;
        }
        else if (*start < (0xE0))
        {
            if (start >= end - 1)
            {
                break;
            }

            if ((start[1] & (0xC0)) != 0x80)
            {
                b_utf8 = false;

                break;
            }

            start += 2;
        }
        else if (*start < (0xF0))
        {
            if (start >= end - 2)
            {
                break;
            }

            if ((start[1] & (0xC0)) != 0x80 || (start[2] & (0xC0)) != 0x80)
            {
                b_utf8 = false;

                break;
            }

            start += 3;
        }
        else
        {
            b_utf8 = false;

            break;
        }
    }

    if (ExcludeAscii)
    {
        if (b_ascii)
        {
            b_utf8 = false;
        }
    }

    return b_utf8;
}

unsigned long long
MakeTime(unsigned long Year, unsigned long Mon, unsigned long Day, unsigned long Hour, unsigned long Min)
{
    char c_year[5];
    char c_mon[5];
    char c_day[5];
    char c_hour[5];
    char c_min[5];

    char c_all[20];

    RtlSecureZeroMemory(c_year, sizeof(c_year));
    RtlSecureZeroMemory(c_mon, sizeof(c_mon));
    RtlSecureZeroMemory(c_day, sizeof(c_day));
    RtlSecureZeroMemory(c_hour, sizeof(c_hour));
    RtlSecureZeroMemory(c_min, sizeof(c_min));
    RtlSecureZeroMemory(c_all, sizeof(c_all));

    ultostr_a(Year, c_year);
    ultostr_a(Mon, c_mon);
    ultostr_a(Day, c_day);
    ultostr_a(Hour, c_hour);
    ultostr_a(Min, c_min);

    if (c_mon[1] == 0)
    {
        c_mon[1] = c_mon[0];
        c_mon[0] = '0';
    }

    if (c_day[1] == 0)
    {
        c_day[1] = c_day[0];
        c_day[0] = '0';
    }

    if (c_hour[1] == 0)
    {
        c_hour[1] = c_hour[0];
        c_hour[0] = '0';
    }

    if (c_min[1] == 0)
    {
        c_min[1] = c_min[0];
        c_min[0] = '0';
    }

    _strcat_a(c_all, c_year);
    _strcat_a(c_all, c_mon);
    _strcat_a(c_all, c_day);
    _strcat_a(c_all, c_hour);
    _strcat_a(c_all, c_min);

    return strtou64_a(c_all);
}

static NTSTATUS
UTF8ToUnicodeN(PWSTR uni_dest, ULONG uni_bytes_max, PULONG uni_bytes_written, PCCH utf8_src, ULONG utf8_bytes)
{
    NTSTATUS status;
    ULONG i, j;
    ULONG written;
    ULONG ch;
    ULONG utf8_trail_bytes;
    WCHAR utf16_ch[3];
    ULONG utf16_ch_len;

    if (!utf8_src)
        return STATUS_INVALID_PARAMETER_4;
    if (!uni_bytes_written)
        return STATUS_INVALID_PARAMETER;

    written = 0;
    status = STATUS_SUCCESS;

    for (i = 0; i < utf8_bytes; i++)
    {
        /* read UTF-8 lead byte */
        ch = (unsigned char)utf8_src[i];
        utf8_trail_bytes = 0;
        if (ch >= 0xf5)
        {
            ch = 0xfffd;
            status = STATUS_SOME_NOT_MAPPED;
        }
        else if (ch >= 0xf0)
        {
            ch &= 0x07;
            utf8_trail_bytes = 3;
        }
        else if (ch >= 0xe0)
        {
            ch &= 0x0f;
            utf8_trail_bytes = 2;
        }
        else if (ch >= 0xc2)
        {
            ch &= 0x1f;
            utf8_trail_bytes = 1;
        }
        else if (ch >= 0x80)
        {
            /* overlong or trail byte */
            ch = 0xfffd;
            status = STATUS_SOME_NOT_MAPPED;
        }

        /* read UTF-8 trail bytes */
        if (i + utf8_trail_bytes < utf8_bytes)
        {
            for (j = 0; j < utf8_trail_bytes; j++)
            {
                if ((utf8_src[i + 1] & 0xc0) == 0x80)
                {
                    ch <<= 6;
                    ch |= utf8_src[i + 1] & 0x3f;
                    i++;
                }
                else
                {
                    ch = 0xfffd;
                    utf8_trail_bytes = 0;
                    status = STATUS_SOME_NOT_MAPPED;
                    break;
                }
            }
        }
        else
        {
            ch = 0xfffd;
            utf8_trail_bytes = 0;
            status = STATUS_SOME_NOT_MAPPED;
            i = utf8_bytes;
        }

        /* encode ch as UTF-16 */
        if ((ch > 0x10ffff) || (ch >= 0xd800 && ch <= 0xdfff) || (utf8_trail_bytes == 2 && ch < 0x00800) ||
            (utf8_trail_bytes == 3 && ch < 0x10000))
        {
            /* invalid codepoint or overlong encoding */
            utf16_ch[0] = 0xfffd;
            utf16_ch[1] = 0xfffd;
            utf16_ch[2] = 0xfffd;
            utf16_ch_len = utf8_trail_bytes;
            status = STATUS_SOME_NOT_MAPPED;
        }
        else if (ch >= 0x10000)
        {
            /* surrogate pair */
            ch -= 0x010000;
            utf16_ch[0] = 0xd800 + (ch >> 10 & 0x3ff);
            utf16_ch[1] = 0xdc00 + (ch >> 0 & 0x3ff);
            utf16_ch_len = 2;
        }
        else
        {
            /* single unit */
            utf16_ch[0] = (WCHAR)ch;
            utf16_ch_len = 1;
        }

        if (!uni_dest)
        {
            written += utf16_ch_len;
            continue;
        }

        for (j = 0; j < utf16_ch_len; j++)
        {
            if (uni_bytes_max >= sizeof(WCHAR))
            {
                *uni_dest++ = utf16_ch[j];
                uni_bytes_max -= sizeof(WCHAR);
                written++;
            }
            else
            {
                uni_bytes_max = 0;
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    *uni_bytes_written = written * sizeof(WCHAR);
    return status;
}

NTSTATUS
UTF8ToUTF16(/*IN*/ char UTF8[_MAX_PATH], /*OUT*/ wchar_t UTF16[_MAX_PATH])
{
    NTSTATUS ns = STATUS_UNSUCCESSFUL;
    ULONG utf16len;
    WCHAR *buf;

    auto UTF8Len = _strlen_a(UTF8);

    ns = UTF8ToUnicodeN(nullptr, 0, &utf16len, UTF8, UTF8Len);
    if (!NT_SUCCESS(ns))
    {
        return ns;
    }

    buf = (WCHAR *)UTF16;
    ns = UTF8ToUnicodeN(buf, utf16len, &utf16len, UTF8, UTF8Len);
    if (!NT_SUCCESS(ns))
    {
        return ns;
    }

    buf[utf16len / sizeof(WCHAR)] = 0;

    return ns;
}

NTSTATUS
UTF16ToAscii(/*IN*/ wchar_t UTF16[_MAX_PATH], /*OUT*/ char Ascii[_MAX_PATH])
{
    NTSTATUS ns = STATUS_UNSUCCESSFUL;

    UNICODE_STRING us;
    ANSI_STRING as;
    char buf[_MAX_PATH] = {0};
    SIZE_T utf16len;

    utf16len = _strlen_w(UTF16) * sizeof(wchar_t);

    as.Buffer = buf;
    as.Length = (USHORT)utf16len;
    as.MaximumLength = (USHORT)(as.Length + sizeof(wchar_t));

    RtlInitUnicodeString(&us, UTF16);

    do
    {
        ns = RtlUnicodeStringToAnsiString(&as, &us, FALSE);
        if (!NT_SUCCESS(ns))
        {
            break;
        }

        memcpy(Ascii, buf, as.Length);

        buf[as.Length] = 0;

    } while (0);

    return ns;
}

static bool
IsMainCert(
    /*IN*/ struct pkcs7_message *Pkcs7,
    /*OUT*/ struct x509_certificate **MainCert)
{
    if (!Pkcs7 || !MainCert)
    {
        return false;
    }

    bool b_ismain = false;

    // Up to 10 cycles, let's say up to 10 certificates

    auto cert = Pkcs7->certs;
    for (int i = 0; i < 10; ++i)
    {
        if (cert && MmIsAddressValid(cert))
        {
            auto subject_tag = cert->subject_tag;
            if (subject_tag != SIGN_NOT_3RDPARTY_TAG)
            {
                b_ismain = true;
                break;
            }
            cert = cert->next;
        }
    }

    if (b_ismain)
    {
        if (cert->subject && MmIsAddressValid(cert->subject))
        {
            *MainCert = cert;
        }
        else
        {
            b_ismain = false;
        }
    }
    else
    {
        // Get the maximum length of the X509 fingerprint ID is generally the main signature (the regular look out, may
        // not be allowed)

        cert = Pkcs7->certs;

        struct x509_certificate *find_cert = NULL;
        unsigned short max_idlen = 0;
        for (int i = 0; i < 10; ++i)
        {
            if (cert && MmIsAddressValid(cert))
            {
                auto idlen = cert->id->len;
                if (idlen > max_idlen)
                {
                    max_idlen = idlen;
                    find_cert = cert;
                }
                cert = cert->next;
            }
        }

        if (find_cert && MmIsAddressValid(find_cert))
        {
            auto raw_akid_size = find_cert->raw_akid_size;
            if (raw_akid_size == SIGN_MAIN_SIG_AKID_SIZE)
            {
                if (find_cert->subject && MmIsAddressValid(find_cert->subject))
                {
                    *MainCert = find_cert;
                    b_ismain = true;
                }
            }
        }
    }

    return b_ismain;
}

bool
GetMainCertInfo(
    /*IN*/ void *PeBuf,
    /*IN*/ unsigned long PeBufLen,
    /*OUT*/ char *CertName,
    /*IN*/ unsigned long CertNameMaxSize,
    /*OUT OPTIONAL*/ unsigned long long *ValidFromTime,
    /*OUT OPTIONAL*/ unsigned long long *ValidToTime)
{
    if (!PeBuf || !CertName || !PeBufLen || !CertNameMaxSize)
    {
        return false;
    }

    if (!MmIsAddressValid(PeBuf))
    {
        return false;
    }

    struct pefile_context ctx;
    int ret;

    RtlSecureZeroMemory(&ctx, sizeof(ctx));

    ret = pefile_parse_binary(PeBuf, PeBufLen, &ctx);
    if (ret < 0)
    {
        return false;
    }

    ret = pefile_strip_sig_wrapper(PeBuf, &ctx);
    if (ret < 0)
    {
        return false;
    }

    if (!ctx.sig_offset)
    {
        return false;
    }
    if (!ctx.sig_len)
    {
        return false;
    }

    auto pstart = (PUCHAR)PeBuf + ctx.sig_offset;
    if (!MmIsAddressValid(pstart))
    {
        return false;
    }

    auto pkcs7 = pkcs7_parse_message(pstart, ctx.sig_len);
    if (!(pkcs7 && MmIsAddressValid(pkcs7)))
    {
        return false;
    }

    struct x509_certificate *main_cert = NULL;
    auto bret = IsMainCert(pkcs7, &main_cert);
    do
    {
        if (!(bret && main_cert))
        {
            break;
        }

        auto subject = main_cert->subject;
        auto subject_len = (unsigned long)strlen(subject);
        if (IsUTF8(subject, subject_len, true))
        {
            wchar_t utf16[_MAX_PATH + sizeof(wchar_t)];

            RtlSecureZeroMemory(utf16, _MAX_PATH + sizeof(wchar_t));
            auto ns = UTF8ToUTF16(subject, utf16);
            if (NT_SUCCESS(ns))
            {
                char ascii[_MAX_PATH + sizeof(char)];
                auto utf16_len = (unsigned long)_strlen_w(utf16);

                RtlSecureZeroMemory(ascii, _MAX_PATH + sizeof(char));

                ns = UTF16ToAscii(utf16, ascii);
                if (NT_SUCCESS(ns))
                {
                    auto ascii_len = (unsigned long)_strlen_a(ascii);
                    memcpy(CertName, ascii, min(ascii_len, CertNameMaxSize));
                }
            }
        }
        else
        {
            memcpy(CertName, subject, min(subject_len, CertNameMaxSize));
        }

        if (ValidFromTime)
        {
            *ValidFromTime = MakeTime(
                main_cert->valid_from_year,
                main_cert->valid_from_mon,
                main_cert->valid_from_day,
                main_cert->valid_from_hour,
                main_cert->valid_from_min);
        }

        if (ValidToTime)
        {
            *ValidToTime = MakeTime(
                main_cert->valid_to_year,
                main_cert->valid_to_mon,
                main_cert->valid_to_day,
                main_cert->valid_to_hour,
                main_cert->valid_to_min);
        }

    } while (0);

    pkcs7_free_message(pkcs7);

    return bret;
}

} // namespace LibSoulExtraction
