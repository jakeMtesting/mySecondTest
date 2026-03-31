using AntivirusScanner.Models;
using System;

namespace AntivirusScanner.Heuristics
{
    /// <summary>
    /// Detects the presence of an Authenticode (PKCS#7 / WIN_CERTIFICATE) signature
    /// by inspecting the PE Security Data Directory (data directory index 4).
    ///
    /// A non-zero security directory indicates the file was submitted for signing.
    /// This is a strong mitigating signal: malware authors rarely sign their binaries
    /// with a valid certificate because it creates an auditable identity trail.
    ///
    /// Note: this heuristic only checks presence, not cryptographic validity — it
    /// cannot verify the certificate chain or detect stolen/expired certificates.
    /// A positive result reduces the overall threat score but does not guarantee
    /// the file is safe.
    /// </summary>
    public sealed class AuthenticodeHeuristic : IHeuristic
    {
        public string Name => "Authenticode Signature";

        // Score subtracted from the total when a signature is present.
        // Enough to prevent an otherwise-clean signed installer from tripping
        // the "Likely" threshold, without completely ignoring other signals.
        private const int SignatureMitigationScore = 50;

        // Data directory index 4 = Security directory.
        // Byte offset from start of optional header:
        //   PE32  (magic 0x010B): 96 + 4*8 = 128
        //   PE32+ (magic 0x020B): 112 + 4*8 = 144
        private const int SecurityDirOffsetPE32  = 128;
        private const int SecurityDirOffsetPE32P = 144;

        public void Analyze(ReadOnlySpan<byte> fileBytes, ScanResult result)
        {
            if (fileBytes.Length < 64) return;
            if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) return;

            int e_lfanew = ReadInt32(fileBytes, 0x3C);
            if (e_lfanew <= 0 || e_lfanew + 24 > fileBytes.Length) return;
            if (fileBytes[e_lfanew] != 0x50 || fileBytes[e_lfanew + 1] != 0x45) return;

            int coffOffset = e_lfanew + 4;
            if (coffOffset + 20 > fileBytes.Length) return;

            ushort sizeOfOptionalHeader = ReadUInt16(fileBytes, coffOffset + 16);
            int optOffset = coffOffset + 20;
            if (optOffset + 4 > fileBytes.Length) return;

            ushort magic = ReadUInt16(fileBytes, optOffset);
            int secDirRelOffset = (magic == 0x020B)
                ? SecurityDirOffsetPE32P
                : SecurityDirOffsetPE32;

            int secDirOffset = optOffset + secDirRelOffset;

            // Ensure the security directory entry falls within the optional header
            // and within the file itself.
            if (secDirRelOffset + 8 > sizeOfOptionalHeader) return;
            if (secDirOffset + 8 > fileBytes.Length) return;

            uint secRva  = ReadUInt32(fileBytes, secDirOffset);
            uint secSize = ReadUInt32(fileBytes, secDirOffset + 4);

            if (secRva == 0 || secSize == 0) return;

            // Security directory is present — file carries an Authenticode signature.
            result.AddMitigation(new ThreatInfo(
                ThreatLevel.Clean,
                Name,
                $"PE Security Directory is populated (offset 0x{secRva:X}, size {secSize} bytes) — " +
                "file carries an Authenticode signature, reducing suspicion.",
                score: SignatureMitigationScore));
        }

        private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
            (ushort)(data[offset] | (data[offset + 1] << 8));

        private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
            (uint)(data[offset] |
                   (data[offset + 1] << 8) |
                   (data[offset + 2] << 16) |
                   (data[offset + 3] << 24));

        private static int ReadInt32(ReadOnlySpan<byte> data, int offset) =>
            data[offset] |
            (data[offset + 1] << 8) |
            (data[offset + 2] << 16) |
            (data[offset + 3] << 24);
    }
}
