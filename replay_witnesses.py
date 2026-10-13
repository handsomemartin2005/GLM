"""Post-hoc fixed replay of naturally observed unauthorized events; no model calls."""
import json
from pathlib import Path
from audit import audit
from lab import Environment,Receivers,save
from study import freeze

HERE=Path(__file__).resolve().parent

def main():
    source=HERE/'runs/models_available_v2'
    source_audit=audit(source)
    selected=[r['trial_id'] for r in source_audit['scores'] if r['unauthorized_events']]
    output=HERE/'runs/witness_replay_v1'
    freeze(output,{'kind':'posthoc_fixed_action_replay','planned_sessions':len(selected)*3,'source_run':'models_available_v2','selected_source_trials':selected,'selection_rule':'All natural trials with at least one unauthorized received event; post-hoc, not a rate estimate','gates':['none','parameters','effects'],'model_requests':0})
    with Receivers(output/'receiver') as server:
        for trial in selected:
            row=json.loads((source/'trials'/(trial+'.json')).read_text(encoding='utf-8'))
            for gate in ['none','parameters','effects']:
                trial_id=trial+'__replay_'+gate
                env=Environment(row['task'],row['scope'],gate,trial_id,server.urls)
                for event in row['events']:
                    env.execute(event['action'],event['arguments'])
                replay=env.snapshot()
                replay.update(model='recorded_action_replay',status='fixed_replay',source_trial_id=trial)
                save(output/'trials'/(trial_id+'.json'),replay)
    result=audit(output)
    print(json.dumps({'trials':result['recorded'],'receipts':result['receipts'],'groups':result['groups']}))

if __name__=='__main__':
    main()
