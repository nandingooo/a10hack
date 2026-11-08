"""Unknown runtime status must not be presented as verified termination."""
import importlib.util
from pathlib import Path

spec=importlib.util.spec_from_file_location('operator_ui',Path(__file__).resolve().parents[1]/'dashboard/server.py')
server=importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


def test_unavailable_engine_is_unknown(monkeypatch):
    def unavailable(*args,**kwargs): raise RuntimeError('Engine unavailable')
    monkeypatch.setattr(server.airlock,'docker',unavailable)
    assert server.run_view(dict(project='test',session_id='s',workspace_id='p',port=1))['status']=='UNKNOWN'


def test_event_archive_reads_beyond_first_page(monkeypatch):
    def api(manifest,path):
        cursor=int(path.rsplit('=',1)[1])
        return {'events':[{'seq':index} for index in range(cursor+1,min(cursor+1000,1501)+1)]}
    monkeypatch.setattr(server.airlock,'api',api)
    data=server.airlock.all_events({})
    assert len(data['events'])==1501
    assert data['events'][-1]['seq']==1501
