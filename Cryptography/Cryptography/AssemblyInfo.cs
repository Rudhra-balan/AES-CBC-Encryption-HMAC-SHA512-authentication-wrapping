﻿using System.Reflection;

namespace Cryptography.Console;

public class AssemblyInfo
{
    public AssemblyInfo(Assembly assembly)
    {
        if (assembly == null)
            throw new ArgumentNullException("assembly");
        this.assembly = assembly;
    }

    private readonly Assembly assembly;

    /// <summary>
    /// Gets the title property
    /// </summary>
    public string ProductTitle
    {
        get
        {
            return GetAttributeValue<AssemblyTitleAttribute>(a => a.Title,
                Path.GetFileNameWithoutExtension(assembly.CodeBase));
        }
    }

    /// <summary>
    /// Gets the application's version
    /// </summary>
    public string Version
    {
        get
        {
            var result = string.Empty;
            var version = assembly.GetName().Version;
            if (version != null)
                return version.ToString();
            else
                return "1.0.0.0";
        }
    }

    /// <summary>
    /// Gets the description about the application.
    /// </summary>
    public string Description
    {
        get { return GetAttributeValue<AssemblyDescriptionAttribute>(a => a.Description); }
    }


    /// <summary>
    ///  Gets the product's full name.
    /// </summary>
    public string Product
    {
        get { return GetAttributeValue<AssemblyProductAttribute>(a => a.Product); }
    }

    /// <summary>
    /// Gets the copyright information for the product.
    /// </summary>
    public string Copyright
    {
        get { return GetAttributeValue<AssemblyCopyrightAttribute>(a => a.Copyright); }
    }

    /// <summary>
    /// Gets the company information for the product.
    /// </summary>
    public string Company
    {
        get { return GetAttributeValue<AssemblyCompanyAttribute>(a => a.Company); }
    }

    private string GetAttributeValue<TAttr>(Func<TAttr,
        string> resolveFunc, string defaultResult = null) where TAttr : Attribute
    {
        var attributes = assembly.GetCustomAttributes(typeof(TAttr), false);
        return attributes.Length > 0 ? resolveFunc((TAttr) attributes[0]) : defaultResult;
    }
}