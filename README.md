# SharpGPOAbuse
SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.

More details can be found at the following blog post: [https://labs.mwrinfosecurity.com/tools/sharpgpoabuse](https://labs.mwrinfosecurity.com/tools/sharpgpoabuse)

## Compile Instructions ## 
SharpGPOAbuse has been built against .NET 3.5 and is compatible with Visual Studio 2017. Simply open the solution file and build the project.

CommandLineParser has been used in order to parse the command line arguments. This package will need to be installed by issuing the following command into the NuGet Package Manager Console:

`Install-Package CommandLineParser -Version 1.9.3.15`

After compiling the project, merge the SharpGPOAbuse.exe and the CommandLine.dll into one executable file using ILMerge:

`ILMerge.exe /out:C:\SharpGPOAbuse.exe C:\Release\SharpGPOAbuse.exe C:\Release\CommandLine.dll`
