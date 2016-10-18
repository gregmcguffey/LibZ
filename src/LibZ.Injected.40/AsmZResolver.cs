#region License

/*
 * Copyright (c) 2013-2014, Milosz Krajewski
 * 
 * Microsoft Public License (Ms-PL)
 * This license governs use of the accompanying software. 
 * If you use the software, you accept this license. 
 * If you do not accept the license, do not use the software.
 * 
 * 1. Definitions
 * The terms "reproduce," "reproduction," "derivative works," and "distribution" have the same 
 * meaning here as under U.S. copyright law.
 * A "contribution" is the original software, or any additions or changes to the software.
 * A "contributor" is any person that distributes its contribution under this license.
 * "Licensed patents" are a contributor's patent claims that read directly on its contribution.
 * 
 * 2. Grant of Rights
 * (A) Copyright Grant- Subject to the terms of this license, including the license conditions 
 * and limitations in section 3, each contributor grants you a non-exclusive, worldwide, 
 * royalty-free copyright license to reproduce its contribution, prepare derivative works of 
 * its contribution, and distribute its contribution or any derivative works that you create.
 * (B) Patent Grant- Subject to the terms of this license, including the license conditions and 
 * limitations in section 3, each contributor grants you a non-exclusive, worldwide, 
 * royalty-free license under its licensed patents to make, have made, use, sell, offer for sale, 
 * import, and/or otherwise dispose of its contribution in the software or derivative works of 
 * the contribution in the software.
 * 
 * 3. Conditions and Limitations
 * (A) No Trademark License- This license does not grant you rights to use any contributors' name, 
 * logo, or trademarks.
 * (B) If you bring a patent claim against any contributor over patents that you claim are infringed 
 * by the software, your patent license from such contributor to the software ends automatically.
 * (C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, 
 * and attribution notices that are present in the software.
 * (D) If you distribute any portion of the software in source code form, you may do so only under this 
 * license by including a complete copy of this license with your distribution. If you distribute 
 * any portion of the software in compiled or object code form, you may only do so under a license 
 * that complies with this license.
 * (E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express
 * warranties, guarantees or conditions. You may have additional consumer rights under your local 
 * laws which this license cannot change. To the extent permitted under your local laws, the 
 * contributors exclude the implied warranties of merchantability, fitness for a particular 
 * purpose and non-infringement.
 */

#endregion

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace LibZ.Injected
{
	/// <summary>
	/// AsmZResolver. Mini resolver getting assemblies straight from resources.
	/// </summary>
	internal class AsmZResolver
	{
		#region consts

		/// <summary>The resource name regular expression.</summary>
		private static readonly Regex ResourceNameRx = new Regex(
			@"asmz://(?<guid>[0-9a-fA-F]{32})/(?<size>[0-9]+)(/(?<flags>[a-zA-Z0-9]*))?",
			RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture);

		/// <summary>The 'this' assembly (please note, this type is going to be embedded into other assemblies)</summary>
		private static readonly Assembly ThisAssembly = typeof(AsmZResolver).Assembly;

		/// <summary>This assembly short name (for debugging).</summary>
		private static readonly string ThisAssemblyName = ThisAssembly.GetName().Name;

		/// <summary>Hash of 'this' assembly name.</summary>
		private static readonly Guid ThisAssemblyGuid = Hash(ThisAssembly.FullName);

		/// <summary>Trace key path.</summary>
		public const string REGISTRY_KEY_PATH = @"Software\Softpark\LibZ";

		/// <summary>Trace key name.</summary>
		public const string REGISTRY_KEY_NAME = @"Trace";

		#endregion

		#region static fields

		/// <summary>The initialized flag.</summary>
		private static int _initialized;

		/// <summary>The resource names found in 'this' assembly.</summary>
		private static readonly Dictionary<Guid, Match> ResourceNames
			= new Dictionary<Guid, Match>();

		/// <summary>The loaded assemblies cache.</summary>
		private static readonly Dictionary<Guid, Assembly> LoadedAssemblies = 
			new Dictionary<Guid, Assembly>();

		/// <summary>Flag indicating if Trace should be used.</summary>
		private static readonly bool UseTrace;

		#endregion

		/// <summary>Initializes the <see cref="AsmZResolver"/> class.</summary>
		static AsmZResolver()
		{
			var value =
				SafeGetRegistryDWORD(false, REGISTRY_KEY_PATH, REGISTRY_KEY_NAME) ??
					SafeGetRegistryDWORD(true, REGISTRY_KEY_PATH, REGISTRY_KEY_NAME) ??
						0;
			UseTrace = value != 0;
		}


		#region public interface

		/// <summary>Initializes resolver.</summary>
		public static void Initialize()
		{
			if (Interlocked.CompareExchange(ref _initialized, 1, 0) != 0) 
				return;

			foreach (var rn in ThisAssembly.GetManifestResourceNames())
			{
				var m = ResourceNameRx.Match(rn);
				if (!m.Success) continue;
				var guid = new Guid(m.Groups["guid"].Value);
				if (ResourceNames.ContainsKey(guid))
				{
					Warn(string.Format("Duplicated assembly id '{0:N}', ignoring.", guid));
				}
				else
				{
					ResourceNames[guid] = m;
				}
			}

			AppDomain.CurrentDomain.AssemblyResolve += AssemblyResolver;
		}

		#endregion

		#region private implementation

		/// <summary>Gets bool value from registry. Note this is a wropper to
		/// isolate access to Registry class which might be a problem on Mono.</summary>
		/// <param name="machine">if set to <c>true</c> "local machine" registry root is used; 
		/// "current user" otherwise.</param>
		/// <param name="path">The path to key.</param>
		/// <param name="name">The name of value.</param>
		/// <returns>Value of given... value.</returns>
		private static uint? SafeGetRegistryDWORD(bool machine, string path, string name)
		{
			try
			{
				return GetRegistryDWORD(machine, path, name);
			}
			catch
			{
				return null;
			}
		}

		/// <summary>Gets bool value from registry.</summary>
		/// <param name="machine">if set to <c>true</c> "local machine" registry root is used; 
		/// "current user" otherwise.</param>
		/// <param name="path">The path to key.</param>
		/// <param name="name">The name of value.</param>
		/// <returns>Value of given... value.</returns>
		private static uint? GetRegistryDWORD(bool machine, string path, string name)
		{
			var root = machine ? Registry.LocalMachine : Registry.CurrentUser;

			var key = root.OpenSubKey(path, false);
			if (key == null)
				return null;

			var value = key.GetValue(name);
			if (value == null)
				return null;

			try
			{
				return Convert.ToUInt32(value);
			}
			catch
			{
				return null;
			}
		}

		/// <summary>Assembly resolver.</summary>
		/// <param name="sender">The sender.</param>
		/// <param name="args">The <see cref="ResolveEventArgs"/> instance containing the event data.</param>
		/// <returns>Loaded assembly or <c>null</c>.</returns>
		private static Assembly AssemblyResolver(object sender, ResolveEventArgs args)
		{
			Debug(string.Format("Resolving: '{0}'", args.Name));

			var name = args.Name;
			var result =
				TryLoadAssembly((IntPtr.Size == 4 ? "x86:" : "x64:") + name) ??
					TryLoadAssembly(name) ??
						TryLoadAssembly((IntPtr.Size == 4 ? "x64:" : "x86:") + name);

			if (result != null)
				Debug(string.Format("Found: '{0}'", args.Name));
			else
				Warn(string.Format("Not found: '{0}'", args.Name));

			return result;
		}

		/// <summary>Tries the load assembly.</summary>
		/// <param name="resourceName">Name of the resource.</param>
		/// <returns>Loaded assembly or <c>null</c>.</returns>
		private static Assembly TryLoadAssembly(string resourceName)
		{
			try
			{
				var guid = Hash(resourceName);
				Match match;
				if (!ResourceNames.TryGetValue(guid, out match)) return null;

				lock (LoadedAssemblies)
				{
					Assembly cached;
					if (LoadedAssemblies.TryGetValue(guid, out cached)) return cached;
				}

				Debug(string.Format("Trying to load '{0}'", resourceName));
				resourceName = match.Groups[0].Value;
				var flags = match.Groups["flags"].Value;
				var size = int.Parse(match.Groups["size"].Value);
				var compressed = flags.Contains("z");
				var unmanaged = flags.Contains("u");
				var portable = flags.Contains("p");

				var buffer = new byte[size];

				using (var rstream = ThisAssembly.GetManifestResourceStream(resourceName))
				{
					if (rstream == null) return null;
					using (var zstream = compressed ? new DeflateStream(rstream, CompressionMode.Decompress) : rstream)
					{
						zstream.Read(buffer, 0, size);
					}
				}

				var loaded = unmanaged || portable
					? LoadUnmanagedAssembly(resourceName, guid, buffer)
					: Assembly.Load(buffer);

				lock (LoadedAssemblies)
				{
					Assembly cached;
					if (LoadedAssemblies.TryGetValue(guid, out cached)) return cached;
					if (loaded != null) LoadedAssemblies[guid] = loaded;
				}

				return loaded;
			}
			catch (Exception e)
			{
				Error(string.Format("{0}: {1}", e.GetType().Name, e.Message));
				return null;
			}
		}

		/// <summary>Loads the unmanaged assembly.</summary>
		/// <param name="resourceName">Name of the assembly.</param>
		/// <param name="guid">The GUID.</param>
		/// <param name="assemblyImage">The assembly binary image.</param>
		/// <returns>Loaded assembly or <c>null</c>.</returns>
		private static Assembly LoadUnmanagedAssembly(string resourceName, Guid guid, byte[] assemblyImage)
		{
			Debug(string.Format("Trying to load as unmanaged/portable assembly '{0}'", resourceName));

			var folderPath = Path.Combine(
				Path.GetTempPath(),
				ThisAssemblyGuid.ToString("N"));
			Directory.CreateDirectory(folderPath);
			var filePath = Path.Combine(folderPath, string.Format("{0:N}.dll", guid));
			var fileInfo = new FileInfo(filePath);

			if (!fileInfo.Exists || fileInfo.Length != assemblyImage.Length)
				File.WriteAllBytes(filePath, assemblyImage);

			return Assembly.LoadFrom(filePath);
		}

		/// <summary>Calculates hash of given text (usually assembly name).</summary>
		/// <param name="text">The text.</param>
		/// <returns>A hash.</returns>
		private static Guid Hash(string text)
		{
			return Create(text);
		}

        /// <summary>
        /// Creates a name-based UUID using the algorithm from RFC 4122 §4.3.
        /// </summary>
        /// <param name="name">The name (within that namespace).</param>
        /// Fixed to use a GUID version of 5 (for SHA-1 hashing).</param>
        /// <returns>A UUID derived from the namespace and name.</returns>
        /// <remarks>See <a href="http://code.logos.com/blog/2011/04/generating_a_deterministic_guid.html">Generating a deterministic GUID</a>.</remarks>
        protected static Guid Create(string name)
        {
            if (name == null)
                throw new ArgumentNullException("name");

            // Use SHA1.
            var version = 5;

            // Pick one of the Namespaces, none match real well.
            var namespaceId = IsoOidNamespace;

            // convert the name to a sequence of octets (as defined by the standard or conventions of its namespace) (step 3)
            // ASSUME: UTF-8 encoding is always appropriate
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);

            // convert the namespace UUID to network order (step 3)
            byte[] namespaceBytes = namespaceId.ToByteArray();
            SwapByteOrder(namespaceBytes);

            // comput the hash of the name space ID concatenated with the name (step 4)
            byte[] hash;
            using (HashAlgorithm algorithm = version == 3 ? (HashAlgorithm)MD5.Create() : SHA1.Create())
            {
                algorithm.TransformBlock(namespaceBytes, 0, namespaceBytes.Length, null, 0);
                algorithm.TransformFinalBlock(nameBytes, 0, nameBytes.Length);
                hash = algorithm.Hash;
            }

            // most bytes from the hash are copied straight to the bytes of the new GUID (steps 5-7, 9, 11-12)
            byte[] newGuid = new byte[16];
            Array.Copy(hash, 0, newGuid, 0, 16);

            // set the four most significant bits (bits 12 through 15) of the time_hi_and_version field to the appropriate 4-bit version number from Section 4.1.3 (step 8)
            newGuid[6] = (byte)((newGuid[6] & 0x0F) | (version << 4));

            // set the two most significant bits (bits 6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively (step 10)
            newGuid[8] = (byte)((newGuid[8] & 0x3F) | 0x80);

            // convert the resulting UUID to local byte order (step 13)
            SwapByteOrder(newGuid);
            return new Guid(newGuid);
        }

        /// <summary>
        /// The namespace for fully-qualified domain names (from RFC 4122, Appendix C).
        /// </summary>
        private static readonly Guid DnsNamespace = new Guid("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

        /// <summary>
        /// The namespace for URLs (from RFC 4122, Appendix C).
        /// </summary>
        private static readonly Guid UrlNamespace = new Guid("6ba7b811-9dad-11d1-80b4-00c04fd430c8");

        /// <summary>
        /// The namespace for ISO OIDs (from RFC 4122, Appendix C).
        /// </summary>
        private static readonly Guid IsoOidNamespace = new Guid("6ba7b812-9dad-11d1-80b4-00c04fd430c8");

        /// <summary>
        /// Converts a GUID (expressed as a byte array) to/from network order (MSB-first).
        /// </summary>
        /// <param name="guid"></param>
        internal static void SwapByteOrder(byte[] guid)
        {
            SwapBytes(guid, 0, 3);
            SwapBytes(guid, 1, 2);
            SwapBytes(guid, 4, 5);
            SwapBytes(guid, 6, 7);
        }

        private static void SwapBytes(byte[] guid, int left, int right)
        {
            byte temp = guid[left];
            guid[left] = guid[right];
            guid[right] = temp;
        }

        private static void Debug(string message)
		{
			if (message != null && UseTrace)
				Trace.TraceInformation("INFO (AsmZ/{0}) {1}", ThisAssemblyName, message);
		}

		private static void Warn(string message)
		{
			if (message != null && UseTrace)
				Trace.TraceWarning("WARN (AsmZ/{0}) {1}", ThisAssemblyName, message);
		}

		private static void Error(string message)
		{
			if (message != null && UseTrace)
				Trace.TraceError("ERROR (AsmZ/{0}) {1}", ThisAssemblyName, message);
		}

		#endregion
	}
}
