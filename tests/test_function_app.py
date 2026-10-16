def test_functions_are_registered():
    import function_app

    names = {fn.get_function_name() for fn in function_app.app.get_functions()}
    assert {
        "scheduled_refresh",
        "manual_refresh",
        "assessment_orchestrator",
        "act_start_run",
        "act_discover",
        "act_inventory",
        "act_rules",
        "act_checklist",
        "act_advisor",
        "act_defender",
        "act_governance",
        "act_finalize",
        "act_fail",
    } <= names
