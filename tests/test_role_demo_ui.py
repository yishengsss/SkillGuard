from tests.role_demo import inject_test_ui


def test_role_demo_injects_warning_inside_body_tag():
    source = b'<!doctype html><html><body class="page"><main>demo</main><script type="module" src="/pages/audit.mjs"></script></body></html>'
    result = inject_test_ui(source, mock_agent=True)
    assert b'<body class="page"><div ' in result
    assert b'NOT an AI audit</div><main>demo</main>' in result
    assert b'class="page">' not in result[result.index(b'</div>') + 6:]
    assert result.count(b'/__test_wallet.mjs') == 1


def test_role_demo_does_not_show_fixture_warning_for_real_model_mode():
    result = inject_test_ui(b'<html><body><script type="module"></script></body></html>', mock_agent=False)
    assert b'TEST MODE' not in result
    assert b'<body><script type="module" src="/__test_wallet.mjs"></script>' in result
