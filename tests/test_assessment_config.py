'''
Tests for private assessment storage configurations.
'''

from pathlib import Path

from src.assessment_config import(
    PROJECT_ROOT,
    ASSESSMENT_DIRECTORY,
    get_assessments_directory
)


def test_assessment_directory_is_inside_project():
    '''
    Verify that the default assessment storage location
    resolved to the project's private data directory.
    '''

    # Determine the expected directory.
    expected_directory = (
        PROJECT_ROOT / 'data' / 'assessments'
    )

    # Verify the configured location.
    assert ASSESSMENT_DIRECTORY == expected_directory
    assert get_assessments_directory() == expected_directory

    # Verify that the directory is represented as a Path.
    assert isinstance(get_assessments_directory(), Path)


def test_get_assessment_directory_has_no_side_effects(
        tmp_path,
        monkeypatch
):
    '''
    Verify that retrieveing the configured path does not
    create the directory or modify the filesystem.
    '''

    # Import the module so we can replace its configured path.
    import src.assessment_config as config

    # Choose a directory that does not exist.
    test_directory = tmp_path / 'private-assessments'

    # Temporarily override the module's configured directory.
    monkeypatch.setattr(
        config,
        'ASSESSMENT_DIRECTORY',
        test_directory
    )

    # Retrieve the configured path.
    result = config.get_assessments_directory()

    # Verify the correct path was returned.
    assert result == test_directory

    # Verify that the directory was not created.
    assert not test_directory.exists()
