using AntivirusScanner.Models;
using System;
using System.Runtime.InteropServices;

namespace AntivirusScanner.Heuristics
{
    /// <summary>
    /// Verifies the Authenticode (PKCS#7) digital signature of a PE file by
    /// calling the native <c>WinVerifyTrust</c> API from <c>wintrust.dll</c>.
    ///
    /// Unlike simply checking whether the Security Data Directory is populated,
    /// this heuristic performs a full cryptographic verification:
    ///   1. Confirms the file's hash matches the signed digest (tamper detection).
    ///   2. Builds and validates the certificate chain to a trusted root.
    ///   3. Checks certificate revocation using locally cached CRL data
    ///      (no network calls are made so scans remain fast offline).
    ///
    /// Outcomes:
    ///   Valid       → −50 score mitigation (trusted, unmodified binary)
    ///   Expired     → −20 score mitigation (content intact, cert time issue only)
    ///   UntrustedRoot → −20 score mitigation (e.g. self-signed internal cert)
    ///   Tampered    → +60 score threat   (signature exists but hash mismatch)
    ///   Unsigned    → no action          (absence of signature is not suspicious alone)
    /// </summary>
    public sealed class AuthenticodeHeuristic : IHeuristic
    {
        public string Name => "Authenticode Signature";

        private const int FullMitigationScore    = 50;
        private const int PartialMitigationScore = 20;
        private const int TamperedScore          = 60;

        public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
        {
            // WinVerifyTrust is Windows-only
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return;

            // Authenticode only applies to PE files
            if (fileBytes.Length < 64) return;
            if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) return;

            SignatureStatus status;
            try
            {
                status = WinTrustVerifier.Verify(result.FilePath);
            }
            catch
            {
                // If WinVerifyTrust itself throws (e.g. DLL not found on Wine),
                // silently skip rather than crashing the scan.
                return;
            }

            switch (status)
            {
                case SignatureStatus.Valid:
                    result.AddMitigation(new ThreatInfo(
                        ThreatLevel.Clean, Name,
                        "Authenticode signature is cryptographically valid — trusted certificate chain, " +
                        "content has not been tampered with.",
                        score: FullMitigationScore));
                    break;

                case SignatureStatus.Expired:
                    result.AddMitigation(new ThreatInfo(
                        ThreatLevel.Clean, Name,
                        "Authenticode signature is present; the signing certificate has expired but the " +
                        "content has not been modified after signing.",
                        score: PartialMitigationScore));
                    break;

                case SignatureStatus.UntrustedRoot:
                    result.AddMitigation(new ThreatInfo(
                        ThreatLevel.Clean, Name,
                        "Authenticode signature is present but the certificate root is not in the " +
                        "Windows trusted store (may be a self-signed or enterprise CA certificate).",
                        score: PartialMitigationScore));
                    break;

                case SignatureStatus.Tampered:
                    // The file carries a signature but its hash doesn't match — strong indicator of
                    // post-signing modification (malware injecting code into a signed binary).
                    result.AddThreat(new ThreatInfo(
                        ThreatLevel.Malicious, Name,
                        "Authenticode signature is INVALID — the file has been modified after signing. " +
                        "This is a strong indicator of malicious code injection into a legitimately signed binary.",
                        score: TamperedScore));
                    break;

                case SignatureStatus.Revoked:
                    result.AddThreat(new ThreatInfo(
                        ThreatLevel.Likely, Name,
                        "Authenticode signing certificate has been REVOKED by the issuing CA. " +
                        "The certificate may have been compromised or used for malicious purposes.",
                        score: 35));
                    break;

                case SignatureStatus.Unsigned:
                case SignatureStatus.Error:
                    // No action — missing signature is not suspicious on its own.
                    break;
            }
        }
    }

    internal enum SignatureStatus
    {
        Valid,
        Unsigned,
        Expired,
        UntrustedRoot,
        Revoked,
        Tampered,
        Error
    }

    /// <summary>
    /// Thin P/Invoke wrapper around the Windows <c>WinVerifyTrust</c> API.
    /// All unmanaged memory is allocated on the unmanaged heap and freed in
    /// finally blocks so no GC interaction is needed.
    /// </summary>
    internal static class WinTrustVerifier
    {
        // Authenticode policy action GUID
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2
            = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        // WinVerifyTrust return values (HRESULT / Win32 error codes)
        private const uint S_OK                        = 0x00000000;
        private const uint TRUST_E_NOSIGNATURE         = 0x800B0100;
        private const uint TRUST_E_NOSIG_2             = 0x800B0101; // sometimes returned for no sig
        private const uint TRUST_E_BAD_DIGEST          = 0x80096010;
        private const uint TRUST_E_EXPLICIT_DISTRUST   = 0x800B0111;
        private const uint TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004;
        private const uint CERT_E_EXPIRED              = 0x800B0101;
        private const uint CERT_E_UNTRUSTEDROOT        = 0x800B0109;
        private const uint CERT_E_CHAINING             = 0x800B010E;
        private const uint CERT_E_REVOKED              = 0x800B010C;
        private const uint CRYPT_E_FILE_ERROR          = 0x80092003;

        // dwUIChoice
        private const uint WTD_UI_NONE = 2;

        // fdwRevocationChecks — check revocation using cached CRL (no network)
        private const uint WTD_REVOKE_WHICHEVER = 1;

        // dwUnionChoice
        private const uint WTD_CHOICE_FILE = 1;

        // dwStateAction
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE  = 2;

        // dwProvFlags — use only locally cached URLs, no network calls
        private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00000010;

        [DllImport("wintrust.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(
            IntPtr hwnd,
            ref Guid pgActionID,
            IntPtr pWVTData);

        /// <summary>
        /// IMAGE_FILE_INFO struct passed to WinVerifyTrust via pFile.
        /// Sequential layout ensures the CLR inserts correct alignment padding
        /// to match the native 64-bit struct layout.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint   cbStruct;        // sizeof(WINTRUST_FILE_INFO)
            public IntPtr pcwszFilePath;   // full path to the file
            public IntPtr hFile;           // optional file handle; 0 = use path
            public IntPtr pgKnownSubject;  // null
        }

        /// <summary>
        /// WINTRUST_DATA struct passed to WinVerifyTrust.
        /// Fields map directly to the Windows SDK struct; the CLR adds implicit
        /// alignment padding after uint fields before IntPtr fields.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint   cbStruct;            // sizeof(WINTRUST_DATA)
            public IntPtr pPolicyCallbackData; // null
            public IntPtr pSIPClientData;      // null
            public uint   dwUIChoice;          // WTD_UI_NONE
            public uint   fdwRevocationChecks; // WTD_REVOKE_WHICHEVER
            public uint   dwUnionChoice;       // WTD_CHOICE_FILE
            public IntPtr pFile;               // pointer to WINTRUST_FILE_INFO (union)
            public uint   dwStateAction;       // WTD_STATEACTION_VERIFY / CLOSE
            public IntPtr hWVTStateData;       // filled by WinVerifyTrust; pass back on CLOSE
            public IntPtr pwszURLReference;    // null
            public uint   dwProvFlags;         // WTD_CACHE_ONLY_URL_RETRIEVAL
            public uint   dwUIContext;         // 0
            public IntPtr pSignatureSettings;  // null (Vista+)
        }

        /// <summary>
        /// Verifies the Authenticode signature of the file at
        /// <paramref name="filePath"/> using <c>WinVerifyTrust</c>.
        /// </summary>
        internal static SignatureStatus Verify(string filePath)
        {
            // --- Allocate native file path string ---
            IntPtr filePathPtr = Marshal.StringToHGlobalUni(filePath);
            try
            {
                // --- Fill and marshal WINTRUST_FILE_INFO ---
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct      = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = filePathPtr,
                    hFile         = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
                try
                {
                    // --- Fill and marshal WINTRUST_DATA ---
                    var trustData = new WINTRUST_DATA
                    {
                        cbStruct            = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                        pPolicyCallbackData = IntPtr.Zero,
                        pSIPClientData      = IntPtr.Zero,
                        dwUIChoice          = WTD_UI_NONE,
                        fdwRevocationChecks = WTD_REVOKE_WHICHEVER,
                        dwUnionChoice       = WTD_CHOICE_FILE,
                        pFile               = fileInfoPtr,
                        dwStateAction       = WTD_STATEACTION_VERIFY,
                        hWVTStateData       = IntPtr.Zero,
                        pwszURLReference    = IntPtr.Zero,
                        dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL,
                        dwUIContext         = 0,
                        pSignatureSettings  = IntPtr.Zero
                    };

                    IntPtr trustDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
                    Marshal.StructureToPtr(trustData, trustDataPtr, false);
                    try
                    {
                        Guid actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                        // Perform the verification
                        uint verifyResult = WinVerifyTrust(
                            new IntPtr(-1),   // INVALID_HANDLE_VALUE = no UI window
                            ref actionId,
                            trustDataPtr);

                        // Read back the state handle so we can free it
                        trustData = Marshal.PtrToStructure<WINTRUST_DATA>(trustDataPtr);

                        // Always call CLOSE to free WinVerifyTrust internal state
                        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                        Marshal.StructureToPtr(trustData, trustDataPtr, false);
                        WinVerifyTrust(new IntPtr(-1), ref actionId, trustDataPtr);

                        return MapResult(verifyResult);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(trustDataPtr);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(fileInfoPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(filePathPtr);
            }
        }

        private static SignatureStatus MapResult(uint result)
        {
            switch (result)
            {
                case S_OK:
                    return SignatureStatus.Valid;

                case TRUST_E_NOSIGNATURE:
                case CRYPT_E_FILE_ERROR:
                    return SignatureStatus.Unsigned;

                case TRUST_E_BAD_DIGEST:
                    // Hash in the signature does not match the file content
                    return SignatureStatus.Tampered;

                case TRUST_E_EXPLICIT_DISTRUST:
                case TRUST_E_SUBJECT_NOT_TRUSTED:
                    // Administrator has explicitly marked this cert as untrusted
                    return SignatureStatus.Tampered;

                case CERT_E_REVOKED:
                    return SignatureStatus.Revoked;

                case CERT_E_UNTRUSTEDROOT:
                case CERT_E_CHAINING:
                    return SignatureStatus.UntrustedRoot;

                default:
                    // 0x800B0101 can mean either CERT_E_EXPIRED or TRUST_E_NOSIG_2
                    // depending on context; treat conservatively as expired.
                    if (result == 0x800B0101)
                        return SignatureStatus.Expired;

                    return SignatureStatus.Error;
            }
        }
    }
}
