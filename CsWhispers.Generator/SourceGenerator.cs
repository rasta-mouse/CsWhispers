using System.Reflection;

using Microsoft.CodeAnalysis;

namespace CsWhispers.Generator;

[Generator]
public sealed class SourceGenerator : ISourceGenerator
{
    public void Initialize(GeneratorInitializationContext context)
    {
        // not required
    }

    public void Execute(GeneratorExecutionContext context)
    {
        // add default files
        context.AddSource("Syscalls.g.cs", GetEmbeddedResource("Syscalls"));
        context.AddSource("DynamicInvoke.g.cs", GetEmbeddedResource("DynamicInvoke"));
        context.AddSource("Native.g.cs", GetEmbeddedResource("Native"));
        context.AddSource("Constants.g.cs", GetEmbeddedResource("Constants"));
        context.AddSource("Usings.g.cs", GetEmbeddedResource("Usings"));
        
        // read config file
        var configFile = context.AdditionalFiles
            .FirstOrDefault(f => f.Path.EndsWith("CsWhispers.txt"));

        // read and parse content
        var content = configFile?.GetText();
        
        if (content is null)
            return;

        var entries = content.Lines.Distinct();
        
        // loop over each entry
        foreach (var entry in entries)
        {
            var line = entry.ToString();
            
            if (string.IsNullOrWhiteSpace(line))
                continue;
            
            // get source file
            var src = GetEmbeddedResource(line);

            if (string.IsNullOrWhiteSpace(src))
            {
                Console.Error.WriteLine($"No source found for {line}.");
                continue;
            }
            
            // add to compilation
            context.AddSource($"{line}.g.cs", src);
        }
    }

    private static string GetEmbeddedResource(string name)
    {
        using var rs = Assembly.GetCallingAssembly()
            .GetManifestResourceStream($"CsWhispers.Generator.Source.{name}.cs");

        if (rs is null)
            return string.Empty;

        using var sr = new StreamReader(rs);
        return sr.ReadToEnd().Trim();
    }
}