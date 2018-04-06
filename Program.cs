using NetFwTypeLib;
using System;
using System.Linq;

namespace WFWCleanup
{
    /// <summary>
    /// WFW cleanup helper.
    /// </summary>
    public class Program
    {
        private static bool _FixAll = false;

        /// <summary>
        /// Cleanups ALL Public inbound rules.
        /// </summary>
        /// <param name="args"></param>
        public static void Main(string[] args)
        {
            _FixAll |= args?.Length > 0 && args[0] != null && args[0].ToLower().EndsWith("all");

            Func<INetFwRule3, bool> filter = r => (_FixAll || r.Enabled)
                && r.Action == NET_FW_ACTION_.NET_FW_ACTION_ALLOW
                && r.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN
                && (r.Profiles & (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC) > 0;

            try
            {
                {
                    var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                    var rules = firewallPolicy.Rules.Cast<INetFwRule3>().ToList();

                    Console.ForegroundColor = ConsoleColor.Green;
                    var rulesToFix = rules.Where(filter).ToList();

                    if (rulesToFix.Count == 0)
                    {
                        Console.WriteLine("No active public rules found.");
                        WaitAndExit(false);
                    }

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    foreach (var rule in rulesToFix)
                    {
                        try
                        {
                            if (rule.Profiles == (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC)
                            {
                                Console.WriteLine("Removing public profile rule: " + rule.Name);
                                firewallPolicy.Rules.Remove(rule.Name);
                                continue;
                            }

                            Console.WriteLine("Removing public profile from rule: " + rule.Name);
                            rule.Profiles = rule.Profiles == (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL
                                ? (int)(NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE)
                                : rule.Profiles ^ (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex.ToString());
                        }
                    }
                }

                GC.Collect(0, GCCollectionMode.Forced, true);

                if (!_FixAll)
                {
                    var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                    var notFixedRules = firewallPolicy.Rules.Cast<INetFwRule3>().Where(filter).ToList();

                    if (notFixedRules.Count == 0)
                        WaitAndExit(true);

                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    foreach (var backDoorRule in notFixedRules)
                    {
                        try
                        {
                            Console.WriteLine("Disabling rule: " + backDoorRule.Name);
                            backDoorRule.Enabled = false;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex.ToString());
                        }
                    }

                    GC.Collect(0, GCCollectionMode.Forced, true);
                }

                {
                    var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                    var notFixedRules = firewallPolicy.Rules.Cast<INetFwRule3>().Where(filter).ToList();

                    if (notFixedRules.Count == 0)
                        WaitAndExit(true);

                    Console.ForegroundColor = ConsoleColor.Red;
                    foreach (var backDoorRule in notFixedRules)
                    {
                        try
                        {
                            Console.WriteLine("Changing profile to private for rule: " + backDoorRule.Name);
                            backDoorRule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex.ToString());
                        }
                    }
                }

                GC.Collect(0, GCCollectionMode.Forced, true);

                {
                    var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                    var notFixedRules = firewallPolicy.Rules.Cast<INetFwRule3>().Where(filter).ToList();

                    if (notFixedRules.Count == 0)
                        WaitAndExit(true);

                    foreach (var backDoorRule in notFixedRules)
                    {
                        Console.WriteLine("New back door rule found: " + backDoorRule.Name);
                        Console.WriteLine("LocalAppPackageId: " + backDoorRule.LocalAppPackageId);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }

            WaitAndExit(false);
        }

        private static void WaitAndExit(bool @fixed)
        {
            if (@fixed)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("All rules was fixed!");
            }

            Console.Write("\r\nPres any key for exit: ");
            Console.ReadKey();

            Environment.Exit(0);
        }
    }
}
