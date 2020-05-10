// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Style", "IDE0017:Simplify object initialization", Justification = "Can't be used on the whole object because of the specific implementation, and doing it only on part of the object isn't as clean", Scope = "member", Target = "~M:NsoElfConverterDotNet.Nx2elf.NsoFile.ToElf~System.Byte[]")]
