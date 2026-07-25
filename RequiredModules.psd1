@{
    <#
        This is only required if you need to use the method PowerShellGet & PSDepend
        It is not required for PSResourceGet or ModuleFast (and will be ignored).
        See Resolve-Dependency.psd1 on how to enable methods.
    #>
    #PSDependOptions             = @{
    #    AddToPath  = $true
    #    Target     = 'output\RequiredModules'
    #    Parameters = @{
    #        Repository = 'PSGallery'
    #    }
    #}

    InvokeBuild                 = '5.14.23'
    PSScriptAnalyzer            = '1.25.0'
    Pester                      = '5.7.1'
    ModuleBuilder               = '3.2.18'
    ChangelogManagement         = '3.1.0'
    Sampler                     = '0.120.0'
    'Sampler.GitHubTasks'       = '0.4.1'



}
