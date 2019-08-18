# SharpGPOAbuse
SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.

More details can be found at the following blog post: [https://labs.mwrinfosecurity.com/tools/sharpgpoabuse](https://labs.mwrinfosecurity.com/tools/sharpgpoabuse)

## Compile Instructions ## 
SharpGPOAbuse has been built against .NET 3.5 and is compatible with Visual Studio 2017. Simply open the solution file and build the project.

CommandLineParser has been used in order to parse the command line arguments. This package will need to be installed by issuing the following command into the NuGet Package Manager Console:

`Install-Package CommandLineParser -Version 1.9.3.15`

After compiling the project, merge the SharpGPOAbuse.exe and the CommandLine.dll into one executable file using ILMerge:

`ILMerge.exe /out:C:\SharpGPOAbuse.exe C:\Release\SharpGPOAbuse.exe C:\Release\CommandLine.dll`

## Usage ##
```
Usage:
        SharpGPOAbuse.exe <AttackType> <AttackOptions>
```

## Attacks Types ## 
Currently SharpGPOAbuse supports the following options:

| Option               | Description                               |
| ---------------------|-------------------------------------------|
| [--AddUserRights](#adding-user-rights) | Add rights to a user                      |
| [--AddLocalAdmin](#adding-a-local-admin)      | Add a user to the local admins group      |
| [--AddComputerScript](#configuring-a-user-or-computer-logon-script)  | Add a new computer startup script         |
| [--AddUserScript](#configuring-a-user-or-computer-logon-script)      | Configure a user logon script             |
| [--AddComputerTask](#configuring-a-computer-or-user-immediate-task)    | Configure a computer immediate task       |
| [--AddUserTask](#configuring-a-computer-or-user-immediate-task)        | Add an immediate task to a user           |

## Attack Options

### Adding User Rights 
```
Options required to add new user rights:
--UserRights
        Set the new rights to add to a user. This option is case sensitive and a comma separeted list must be used.
--UserAccount
        Set the account to add the new rights.
--GPOName
        The name of the vulnerable GPO.
```

### Adding a Local Admin 
```
Options required to add a new local admin:
--UserAccount
        Set the name of the account to be added in local admins.
--GPOName
        The name of the vulnerable GPO.
```

### Configuring a User or Computer Logon Script  
```
Options required to add a new user or computer startup script:
--ScriptName
        Set the name of the new startup script.
--ScriptContents
        Set the contents of the new startup script.
--GPOName
        The name of the vulnerable GPO.
```

### Configuring a Computer or User Immediate Task  
```
Options required to add a new computer or user immediate task:
--TaskName
        Set the name of the new computer task.
--Author
        Set the author of the new task (use a DA account).
--Command
        Command to execute.
--Arguments
        Arguments passed to the command.
--GPOName
        The name of the vulnerable GPO.
```

## Additional Options ##
| Option               | Description                               |
| ---------------------|-------------------------------------------|
| --DomainController   | Set the target domain controller          |
| --Domain             | Set the target domain                     |
| --Force              | Overwrite existing files if required      | 
