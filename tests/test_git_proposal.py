from pathlib import Path
import pytest
from git_proposal import prepare
from policy import BASE, PATH, Rejected
from engine import GOOD

def fixture(tmp_path):
    (tmp_path/'src').mkdir()
    (tmp_path/PATH).write_text(BASE)
    return tmp_path

def test_good_only_changes_allowed_file(tmp_path):
    root=fixture(tmp_path); result=prepare(GOOD,root)
    assert (root/PATH).read_text()==GOOD['after']
    assert result['merge_authorized'] is False
    assert result['deployment_authorized'] is False
    assert len(list(root.rglob('*.py')))==1

def test_forbidden_action_has_no_write(tmp_path):
    root=fixture(tmp_path)
    with pytest.raises(Rejected): prepare({'tool':'read_secret','path':PATH},root)
    assert (root/PATH).read_text()==BASE

def test_changed_base_has_no_write(tmp_path):
    root=fixture(tmp_path);(root/PATH).write_text('changed')
    with pytest.raises(Rejected): prepare(GOOD,root)
    assert (root/PATH).read_text()=='changed'

def test_symlink_rejected(tmp_path):
    root=fixture(tmp_path);target=root/'other';target.write_text(BASE)
    (root/PATH).unlink();(root/PATH).symlink_to(target)
    with pytest.raises(Rejected): prepare(GOOD,root)
    assert target.read_text()==BASE
