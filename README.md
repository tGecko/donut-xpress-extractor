# Minimal Donut XPRESS Extractor (Windows)

This is a minimal, Windows-only extractor and decompressor for XPRESS-compressed [donut](https://github.com/TheWover/donut) payloads.  
None of the tools we found to extract/decompress donut payloads worked for XPRESS compression.

I do not have multiple samples to test this with - if you run into issues, let me know.

It scans up until `max-start` for a header consisting of **compressed size** and **decompressed size** (little-endian). If a plausible header is found, it uses `RtlDecompressBuffer` from `ntdll.dll` (XPRESS, `COMPRESSION_FORMAT_XPRESS = 0x0003`) to decompress the payload and writes it to the specified output path.

## Usage

```
python donut_xpress_extract.py -i <input_file> -o <output_file> [--max-start 0x2000]
```

## Sample Output

```
[+] Header @          0x1285
[+] Compressed data @ 0x128D
    Comp size       : 0xA47389
    Decomp size     : 0x13FA800
    Decomp result   : 0x13FA800 -> OK
[+] Wrote to: outfile.bin
```
