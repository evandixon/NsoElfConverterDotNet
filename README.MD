# NsoElfConverterDotNet

Simple .Net library to convert NSO executables to and from ELF.

## Usage

### C#
```
INsoElfConverter converter = NsoElfConverter.Instance;

// NSO to ELF
byte[] elfData = converter.ConvertNsoToElf(File.ReadAllBytes("main"));

// ELF to NSO
byte[] nsoData = converter.ConvertElfToNso(elfData);
```

### Console
This is primarily intended as a way to manually test the library, but should still be a servicable command-line utility.

```
Usage:
dotnet NsoElfConverterDotNet.dll <main> <main.elf>
or
dotnet NsoElfConverterDotNet.dll <main.elf> <main>
```

## Credits

- [shuffle2](https://github.com/shuffle2) for [nx2elf](https://github.com/shuffle2/nx2elf), which [I forked](https://github.com/evandixon/nx2elf) and bundled
- [switchbrew](https://github.com/switchbrew) for [switch-tools](https://github.com/switchbrew/switch-tools), parts of which I ported to C#
