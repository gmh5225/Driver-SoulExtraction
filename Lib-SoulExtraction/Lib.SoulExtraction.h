#pragma once

namespace LibSoulExtraction {

bool
GetMainCertInfo(
    /*IN*/ void *PeBuf,
    /*IN*/ unsigned long PeBufLen,
    /*OUT*/ char *CertName,
    /*IN*/ unsigned long CertNameMaxSize,
    /*OUT OPTIONAL*/ unsigned long long *ValidFromTime,
    /*OUT OPTIONAL*/ unsigned long long *ValidToTime);

}
