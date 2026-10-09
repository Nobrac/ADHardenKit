@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Interactive console tool: coloured output is the user interface, not pipeline data.
        'PSAvoidUsingWriteHost'
        # Empty catches are deliberate fallbacks (window width, optional attributes, probes
        # whose absence is reported elsewhere).
        'PSAvoidUsingEmptyCatchBlock'
        # False positives: every flagged remote script block takes its input through param().
        'PSUseUsingScopeModifierInNewRunspaces'
        # Report and summary builders only write files the run owns.
        'PSUseShouldProcessForStateChangingFunctions'
        'PSUseSingularNouns'
    )
}
