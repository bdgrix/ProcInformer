using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;

namespace ProcessThreadMonitor
{
    class Program
    {
        private const int CHECK_INTERVAL = 5000;
        private const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        
        private static readonly HashSet<string> _seenThreads = new HashSet<string>();
        private static readonly object _lockObject = new object();
        private static string _outputFile = "";
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetThreadDescription(IntPtr hThread, out IntPtr ppszThreadDescription);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryThreadCycleTime(IntPtr ThreadHandle, out ulong CycleTime);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, 
            ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        static void Main(string[] args)
        {
            Console.Clear();
            ShowBanner();
            
            _outputFile = $"output-{DateTime.Now:yyyy-MM-dd-HH-mm-ss}.gtxt";
            
            EnableDebugPrivilege();
            
            File.WriteAllText(_outputFile, $"Process Thread Monitor - Started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");
            File.AppendAllText(_outputFile, "Tracking NEW threads only (no duplicates)\n");
            File.AppendAllText(_outputFile, "=================================================================\n\n");
            
            WriteColor("Monitoring Started!", ConsoleColor.Green);
            WriteColor($"Output File: {_outputFile}", ConsoleColor.Cyan);
            WriteColor("Tracking NEW threads only (no duplicates)", ConsoleColor.Yellow);
            WriteColor("Press Ctrl+C to stop monitoring and save output", ConsoleColor.Magenta);
            WriteColor("", ConsoleColor.White);
            
            WriteColor("Monitoring Information:", ConsoleColor.White);
            WriteColor($"   Scan Interval: {CHECK_INTERVAL/1000} seconds", ConsoleColor.Gray);
            WriteColor($"   Thread Name Column: 130 characters", ConsoleColor.Gray);
            WriteColor($"   SeDebugPrivilege: Enabled", ConsoleColor.Gray);
            WriteColor($"   Duplicate Prevention: Active", ConsoleColor.Gray);
            WriteColor("", ConsoleColor.White);

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                WriteColor("Shutting down monitor...", ConsoleColor.Red);
                File.AppendAllText(_outputFile, $"\nMonitoring stopped at {DateTime.Now:HH:mm:ss}\n");
                File.AppendAllText(_outputFile, $"Total unique threads recorded: {_seenThreads.Count}\n");
                WriteColor($"Output saved to: {_outputFile}", ConsoleColor.Green);
                WriteColor($"Total unique threads recorded: {_seenThreads.Count}", ConsoleColor.Cyan);
                Thread.Sleep(2000);
                Environment.Exit(0);
            };

            while (true)
            {
                try
                {
                    MonitorAllProcesses();
                    Thread.Sleep(CHECK_INTERVAL);
                }
                catch (Exception ex)
                {
                    WriteColor($"Error in monitoring loop: {ex.Message}", ConsoleColor.Red);
                }
            }
        }

        static void ShowBanner()
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine(@"  _____                _____        __                               ");
            Console.WriteLine(@" |  __ \              |_   _|      / _|                              ");
            Console.WriteLine(@" | |__) | __ ___   ___  | |  _ __ | |_ ___  _ __ _ __ ___   ___ _ __ ");
            Console.WriteLine(@" |  ___/ '__/ _ \ / __| | | | '_ \|  _/ _ \| '__| '_ ` _ \ / _ \ '__|");
            Console.WriteLine(@" | |   | | | (_) | (__ _| |_| | | | || (_) | |  | | | | | |  __/ |   ");
            Console.WriteLine(@" |_|   |_|  \___/ \___|_____|_| |_|_| \___/|_|  |_| |_| |_|\___|_|   ");
            Console.WriteLine();
            
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("               Process Thread Monitor v1.0 - Real-time Thread Discovery");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("               =======================================================");
            Console.WriteLine();
            Console.ResetColor();
        }

        static void WriteColor(string message, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ResetColor();
        }

        static void EnableDebugPrivilege()
        {
            try
            {
                WriteColor("Enabling SeDebugPrivilege...", ConsoleColor.Yellow);
                
                IntPtr tokenHandle;
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
                {
                    WriteColor("Failed to open process token. Run as Administrator.", ConsoleColor.Red);
                    return;
                }

                LUID luid = new LUID();
                if (!LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid))
                {
                    WriteColor("Failed to lookup privilege value.", ConsoleColor.Red);
                    CloseHandle(tokenHandle);
                    return;
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES();
                tokenPrivileges.PrivilegeCount = 1;
                tokenPrivileges.Privileges = new LUID_AND_ATTRIBUTES[1];
                tokenPrivileges.Privileges[0].Luid = luid;
                tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                if (!AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    WriteColor("Failed to adjust token privileges.", ConsoleColor.Red);
                }
                else
                {
                    WriteColor("SeDebugPrivilege enabled successfully.", ConsoleColor.Green);
                }

                CloseHandle(tokenHandle);
            }
            catch (Exception ex)
            {
                WriteColor($"Error enabling debug privilege: {ex.Message}", ConsoleColor.Red);
            }
        }

        static void MonitorAllProcesses()
        {
            try
            {
                Process[] allProcesses = Process.GetProcesses();
                StringBuilder output = new StringBuilder();
                int newThreadsCount = 0;
                int accessibleProcesses = 0;
                
                foreach (Process process in allProcesses)
                {
                    try
                    {
                        if (process.Id == 0) continue;

                        string processInfo = $"{process.ProcessName} (PID: {process.Id})";
                        int processNewThreads = BuildProcessThreadTable(process, processInfo, output);
                        newThreadsCount += processNewThreads;
                        accessibleProcesses++;
                    }
                    catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException)
                    {
                        continue;
                    }
                }

                if (newThreadsCount > 0)
                {
                    File.AppendAllText(_outputFile, output.ToString());
                    File.AppendAllText(_outputFile, $"\n[{DateTime.Now:HH:mm:ss}] Found {newThreadsCount} new threads\n\n");
                    
                    WriteColor($"[{DateTime.Now:HH:mm:ss}] Found {newThreadsCount} new threads in {accessibleProcesses}/{allProcesses.Length} processes", ConsoleColor.Green);
                }
                else
                {
                    WriteColor($"[{DateTime.Now:HH:mm:ss}] Scanned {accessibleProcesses}/{allProcesses.Length} processes - No new threads", ConsoleColor.Blue);
                }
                
                if (newThreadsCount > 0 || DateTime.Now.Second % 30 == 0)
                {
                    WriteColor($"Current Stats: {_seenThreads.Count} unique threads tracked", ConsoleColor.Cyan);
                }
            }
            catch (Exception ex)
            {
                WriteColor($"[ERROR] Failed to enumerate processes: {ex.Message}", ConsoleColor.Red);
            }
        }

        static int BuildProcessThreadTable(Process process, string processInfo, StringBuilder output)
        {
            try
            {
                ProcessThreadCollection threads = process.Threads;
                if (threads.Count == 0)
                    return 0;

                var newThreadData = new List<ThreadInfo>();
                
                foreach (ProcessThread thread in threads.Cast<ProcessThread>())
                {
                    try
                    {
                        var info = GetThreadInfo(thread, process.Id);
                        if (info != null)
                        {
                            string threadKey = $"{process.Id}-{thread.Id}-{info.StartAddress}";
                            
                            lock (_lockObject)
                            {
                                if (!_seenThreads.Contains(threadKey))
                                {
                                    _seenThreads.Add(threadKey);
                                    newThreadData.Add(info);
                                }
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                if (newThreadData.Count == 0)
                    return 0;

                string table = CreateTable(processInfo, newThreadData);
                output.AppendLine(table);
                output.AppendLine();

                return newThreadData.Count;
            }
            catch (Exception)
            {
                return 0;
            }
        }

        static string CreateTable(string processInfo, List<ThreadInfo> threads)
        {
            var sb = new StringBuilder();
            
            sb.AppendLine($"Process: {processInfo}");
            sb.AppendLine($"New Threads Found: {threads.Count}");
            sb.AppendLine();

            sb.AppendLine("  ┌────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────┬────────────┬────────────┬────────────────┬────────────────┐");
            sb.AppendLine("  │ Thread ID  │ Thread Name                                                                                                                            │ Base Pri   │ Curr Pri   │ Pri Symbol │ Start Address  │ CPU Cycles     │");
            sb.AppendLine("  ├────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┼────────────┼────────────┼────────────────┼────────────────┤");

            foreach (var thread in threads)
            {
                string row = string.Format("  │ {0,-10} │ {1,-128} │ {2,-10} │ {3,-10} │ {4,-10} │ {5,-14} │ {6,-14} │",
                    thread.ThreadId.ToString(),
                    TruncateString(thread.ThreadName ?? "N/A", 128),
                    thread.BasePriority.ToString(),
                    thread.CurrentPriority.ToString(),
                    thread.PrioritySymbolic ?? "UNKNOWN",
                    thread.StartAddress ?? "0x0",
                    thread.CpuCycles.ToString("X16"));
                
                sb.AppendLine(row);
            }

            sb.AppendLine("  └────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────┴────────────┴────────────┴────────────────┴────────────────┘");

            return sb.ToString();
        }

        static string TruncateString(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return "N/A";
            return value.Length <= maxLength ? value : value.Substring(0, maxLength - 3) + "...";
        }

        static ThreadInfo? GetThreadInfo(ProcessThread thread, int processId)
        {
            try
            {
                int threadId = thread.Id;
                string threadName = GetThreadName(threadId, processId);
                string startAddress = "0x" + thread.StartAddress.ToString("X");
                int currentPriority = thread.CurrentPriority;
                int basePriority = thread.BasePriority;
                string prioritySymbolic = GetPrioritySymbolic(thread.PriorityLevel);
                ulong cpuCycles = GetThreadCycleTime(threadId, processId);

                return new ThreadInfo
                {
                    ThreadId = threadId,
                    ThreadName = threadName,
                    StartAddress = startAddress,
                    CurrentPriority = currentPriority,
                    BasePriority = basePriority,
                    PrioritySymbolic = prioritySymbolic,
                    CpuCycles = cpuCycles
                };
            }
            catch
            {
                return null;
            }
        }

        static string GetPrioritySymbolic(ThreadPriorityLevel priority)
        {
            switch (priority)
            {
                case ThreadPriorityLevel.Idle: return "IDLE";
                case ThreadPriorityLevel.Lowest: return "LOWEST";
                case ThreadPriorityLevel.BelowNormal: return "BELOW_NORM";
                case ThreadPriorityLevel.Normal: return "NORMAL";
                case ThreadPriorityLevel.AboveNormal: return "ABOVE_NORM";
                case ThreadPriorityLevel.Highest: return "HIGHEST";
                case ThreadPriorityLevel.TimeCritical: return "TIME_CRIT";
                default: return "UNKNOWN";
            }
        }

        static ulong GetThreadCycleTime(int threadId, int processId)
        {
            IntPtr threadHandle = IntPtr.Zero;
            try
            {
                threadHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, (uint)threadId);
                if (threadHandle == IntPtr.Zero)
                    return 0;

                ulong cycleTime;
                if (QueryThreadCycleTime(threadHandle, out cycleTime))
                    return cycleTime;

                return 0;
            }
            finally
            {
                if (threadHandle != IntPtr.Zero)
                    CloseHandle(threadHandle);
            }
        }

        static string GetThreadName(int threadId, int processId)
        {
            IntPtr threadHandle = IntPtr.Zero;
            IntPtr namePtr = IntPtr.Zero;
            
            try
            {
                threadHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, (uint)threadId);
                if (threadHandle == IntPtr.Zero)
                    return "NO_ACCESS";

                int result = GetThreadDescription(threadHandle, out namePtr);
                if (result == 0 || namePtr == IntPtr.Zero)
                    return "NO_NAME";

                string? threadName = Marshal.PtrToStringUni(namePtr);
                return string.IsNullOrEmpty(threadName) ? "EMPTY" : threadName;
            }
            catch
            {
                return "ERROR";
            }
            finally
            {
                if (namePtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(namePtr);
                
                if (threadHandle != IntPtr.Zero)
                    CloseHandle(threadHandle);
            }
        }

        class ThreadInfo
        {
            public int ThreadId { get; set; }
            public string ThreadName { get; set; } = string.Empty;
            public string StartAddress { get; set; } = string.Empty;
            public int CurrentPriority { get; set; }
            public int BasePriority { get; set; }
            public string PrioritySymbolic { get; set; } = string.Empty;
            public ulong CpuCycles { get; set; }
        }
    }
}