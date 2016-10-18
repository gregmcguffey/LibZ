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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using LibZ.Msil;
using LibZ.Tool.InjectIL;
using Mono.Cecil;
using NLog;

namespace LibZ.Tool.Tasks
{
	/// <summary>
	///     Base class for all tasks.
	///     Contains some utilities potentially used by all of them.
	/// </summary>
	public class TaskBase
	{
		#region consts

		/// <summary>Logger for this class.</summary>
		private static readonly Logger Log = LogManager.GetCurrentClassLogger();

		/// <summary>Hash calculator.</summary>
		private static readonly SHA1 HashAlgorithm = SHA1CryptoServiceProvider.Create();

		/// <summary>The regular expression to parse resource name</summary>
		protected static readonly Regex ResourceNameRx = new Regex(
			@"asmz://(?<guid>[0-9a-fA-F]{32})/(?<size>[0-9]+)(/(?<flags>[a-zA-Z0-9]*))?",
			RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture);

		/// <summary>The regular expression to detect portable assemblies.</summary>
		protected static readonly Regex PortableAssemblyRx = new Regex(
			@"(^|,)\s*Retargetable\s*\=\s*Yes\s*(,|$)",
			RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture);

		#endregion

		#region static fields

		/// <summary>The wildcard cache.</summary>
		private static readonly Dictionary<string, Regex> WildcardCacheRx = new Dictionary<string, Regex>();

		#endregion

		#region file utilities

		/// <summary>Renames the file.</summary>
		/// <param name="sourceFileName">Name of the source file.</param>
		/// <param name="targetFileName">Name of the target file.</param>
		protected static void RenameFile(string sourceFileName, string targetFileName)
		{
			try
			{
				var tempFileName = String.Format("{0}.{1:N}", targetFileName, Guid.NewGuid());
				File.Move(targetFileName, tempFileName);
				File.Move(sourceFileName, targetFileName);
				File.Delete(tempFileName);
			}
			catch
			{
				Log.Error("Renaming to '{0}' failed", targetFileName);
				throw;
			}
		}

		/// <summary>Deletes the file.</summary>
		/// <param name="fileName">Name of the file.</param>
		protected static void DeleteFile(string fileName)
		{
			if (!File.Exists(fileName))
				return;

			try
			{
				File.Delete(fileName);
			}
				// ReSharper disable EmptyGeneralCatchClause
			catch
			{
				Log.Warn("File '{0}' could not be deleted", fileName);
			}
			// ReSharper restore EmptyGeneralCatchClause
		}

		/// <summary>Finds the files.</summary>
		/// <param name="includePatterns">The include patterns.</param>
		/// <param name="excludePatterns">The exclude patterns.</param>
		/// <returns>Collection of file names.</returns>
		protected static IEnumerable<string> FindFiles(
			IEnumerable<string> includePatterns,
			IEnumerable<string> excludePatterns = null)
		{
			if (excludePatterns == null)
				excludePatterns = new string[0];
			var result = includePatterns.SelectMany(p => FindFiles(p, excludePatterns))
				.Distinct()
				.ToList();
			result.Sort((l, r) => string.Compare(l, r, StringComparison.InvariantCultureIgnoreCase));
			return result;
		}

		/// <summary>Finds the files.</summary>
		/// <param name="pattern">The pattern.</param>
		/// <param name="excludePatterns">The exclude patterns.</param>
		/// <returns>Collection of file names.</returns>
		private static IEnumerable<string> FindFiles(string pattern, IEnumerable<string> excludePatterns)
		{
			if (!Path.IsPathRooted(pattern))
				pattern = ".\\" + pattern;
			var directoryName = Path.GetDirectoryName(pattern) ?? ".";
			var searchPattern = Path.GetFileName(pattern) ?? "*.dll";

			return Directory.GetFiles(directoryName, searchPattern)
				.Where(fn => !excludePatterns.Any(
					ep => WildcardToRegex(ep).IsMatch(Path.GetFileName(fn) ?? String.Empty)));
		}

		/// <summary>Converts wildcard to regex.</summary>
		/// <param name="pattern">The pattern.</param>
		/// <returns>Regex.</returns>
		private static Regex WildcardToRegex(string pattern)
		{
			Regex rx;
			if (!WildcardCacheRx.TryGetValue(pattern, out rx))
			{
				var p = String.Format("^{0}$", Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", "."));
				WildcardCacheRx[pattern] = rx = new Regex(p, RegexOptions.IgnoreCase);
			}
			return rx;
		}

		#endregion

		#region exceptions

		/// <summary>Returns ArgumentNullException.</summary>
		/// <param name="argumentName">Name of the argument.</param>
		/// <returns>ArgumentNullException</returns>
		protected static ArgumentNullException ArgumentNull(string argumentName)
		{
			return new ArgumentNullException(argumentName);
		}

		/// <summary>Returns FileNotFoundException.</summary>
		/// <param name="fileName">Name of the file.</param>
		/// <returns>FileNotFoundException</returns>
		protected static FileNotFoundException FileNotFound(string fileName)
		{
			return new FileNotFoundException(String.Format("File '{0}' could not be found", fileName));
		}

		#endregion

		#region utilities

		/// <summary>Returns a hash of given resource.</summary>
		/// <param name="resource">The resource.</param>
		/// <returns>Hash already in resource name.</returns>
		protected static Guid? Hash(Resource resource)
		{
			var m = ResourceNameRx.Match(resource.Name);
			if (!m.Success)
				return null;
			return new Guid(m.Groups["guid"].Value);
		}

		/// <summary>Hashes the specified text.</summary>
		/// <param name="text">The text.</param>
		/// <returns>Hash of given text.</returns>
		protected static Guid Hash(string text)
		{
            return Create(text);
		}

		/// <summary>Hashes the specified text.</summary>
		/// <param name="text">The text.</param>
		/// <returns>String representation of the hash.</returns>
		protected static string HashString(string text)
		{
			return Hash(text).ToString("N").ToLowerInvariant();
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

        #endregion

        #region assembly manipulation

        /// <summary>Injects the DLL.</summary>
        /// <param name="targetAssembly">The target assembly.</param>
        /// <param name="sourceAssembly">The source assembly.</param>
        /// <param name="sourceAssemblyBytes">The source assembly bytes.</param>
        /// <param name="overwrite">
        ///     if set to <c>true</c> overwrites existing resource.
        /// </param>
        /// <returns>
        ///     <c>true</c> if assembly has been injected.
        /// </returns>
        protected static bool InjectDll(
			AssemblyDefinition targetAssembly,
			AssemblyDefinition sourceAssembly, byte[] sourceAssemblyBytes,
			bool overwrite)
		{
			var flags = String.Empty;
			if (!MsilUtilities.IsManaged(sourceAssembly))
				flags += "u";
			if (MsilUtilities.IsPortable(sourceAssembly))
				flags += "p";

			var input = sourceAssemblyBytes;
			var output = DefaultCodecs.DeflateEncoder(input);

			if (output.Length < input.Length)
			{
				flags += "z";
			}
			else
			{
				output = input;
			}

			var architecture = MsilUtilities.GetArchitecture(sourceAssembly);
			var architecturePrefix =
				architecture == AssemblyArchitecture.X64 ? "x64:" :
					architecture == AssemblyArchitecture.X86 ? "x86:" :
						string.Empty;
			var guid = Hash(architecturePrefix + sourceAssembly.FullName);

			var resourceName = String.Format(
				"asmz://{0:N}/{1}/{2}",
				guid, input.Length, flags);

			var existing = targetAssembly.MainModule.Resources
				.Where(r => Hash(r) == guid)
				.ToArray();

			if (existing.Length > 0)
			{
				if (overwrite)
				{
					Log.Warn("Resource '{0}' already exists and is going to be replaced.", resourceName);
					foreach (var r in existing)
						targetAssembly.MainModule.Resources.Remove(r);
				}
				else
				{
					Log.Warn("Resource '{0}' already exists and will be skipped.", resourceName);
					return false;
				}
			}

			var resource = new EmbeddedResource(
				resourceName,
				ManifestResourceAttributes.Public,
				output);

			targetAssembly.MainModule.Resources.Add(resource);

			return true;
		}

		/// <summary>Instruments assembly with AsmZ resolver.</summary>
		/// <param name="targetAssembly">The target assembly.</param>
		protected static void InstrumentAsmZ(AssemblyDefinition targetAssembly)
		{
			var helper = new InstrumentHelper(targetAssembly);
			helper.InjectLibZInitializer();
			helper.InjectAsmZResolver();
		}

		/// <summary>Validates if AsmZResolver can be injected.</summary>
		/// <param name="assembly">The target assembly.</param>
		/// <exception cref="System.ArgumentException">If assembly is targeting unsupported version.</exception>
		protected static void ValidateAsmZInstrumentation(AssemblyDefinition assembly)
		{
			var version = MsilUtilities.GetFrameworkVersion(assembly);
			if (version >= new Version("4.0.0.0"))
				return;
			if (version < new Version("2.0.0.0") || version == new Version("2.0.5.0"))
				throw new ArgumentException(
					string.Format("Cannot inject code into assemblies targeting '{0}'", version));
			if (version < new Version("3.5.0.0"))
			{
				Log.Warn(string.Format("Attempting to inject AsmZResolver into assembly targeting framework '{0}'.", version));
				Log.Warn("AsmZResolver should work but is neither designed nor tested with this framework.");
			}
		}

		/// <summary>Validates if LibZResolver can be injected.</summary>
		/// <param name="assembly">The target assembly.</param>
		/// <exception cref="System.ArgumentException">If assembly is targeting unsupported version.</exception>
		protected static void ValidateLibZInstrumentation(AssemblyDefinition assembly)
		{
			var version = MsilUtilities.GetFrameworkVersion(assembly);
			if (version >= new Version("4.0.0.0"))
				return;
			if (version < new Version("2.0.0.0") || version == new Version("2.0.5.0"))
				throw new ArgumentException(
					string.Format("Cannot inject code into assemblies targeting '{0}'", version));
			if (version < new Version("3.5.0.0"))
			{
				Log.Warn(string.Format("Attempting to inject assemblies into assembly targeting '{0}'.", version));
				Log.Warn("LibZResolver will work only if .NET 3.5 is also installed on target machine");
			}
		}

		#endregion
	}
}