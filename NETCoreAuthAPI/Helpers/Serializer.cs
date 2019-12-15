using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace NETCoreAuthAPI.Utilities
{
    public static class Serializer
    {

        public static void Clone<T>(T fromObj, T toObj)
        {
            try
            {
                PropertyInfo[] properties1 = fromObj.GetType().GetProperties();
                PropertyInfo[] properties2 = toObj.GetType().GetProperties();
                foreach (PropertyInfo p1 in properties1)
                {
                    if (p1.Name.ToUpper(CultureInfo.CurrentCulture) == "ID") continue;
                    if (p1.Name.StartsWith("n_", StringComparison.Ordinal)) continue;
                    foreach (PropertyInfo p2 in properties2)
                    {
                        if (p1.Name == p2.Name)
                        {
                            if (p1.CanRead && p2.CanWrite)
                            {
                                p2.SetValue(toObj, p1.GetValue(fromObj, null), null);
                            }
                            break;
                        }
                    }
                }

            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"ArgumentException Unable to clone object: '{ex}'");
            }
        }

    }
}
