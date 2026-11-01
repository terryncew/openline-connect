"""Blank independent receiver scaffold. Implement YOUR authorization; never rely on a wrapper precheck."""
class IndependentRobotReceiver:
    def __init__(self, workcell_dir, owner_public_key, receiver_private_key):
        self.workcell_dir = workcell_dir
        self.owner_public_key = owner_public_key
        self.receiver_private_key = receiver_private_key
    def admit(self, signed_permit, signed_worker_request):
        """Verify factory, worker, epoch, config, SOP, task bounds, cap, effect_id.
        Call your *own controller* with a receiver-bound token, commit own receipt,
        and expose independently auditable controller evidence. No model/robot hardware.
        """
        raise NotImplementedError("Independent implementation required")
    def recover(self, signed_current_worker, job_effect_id):
        """Verify current worker rights *before* disclosing historical result; never execute."""
        raise NotImplementedError("Independent implementation required")
    def apply_signed_change(self, event, facility_manifest):
        """Verify change chain, invalidate affected new admissions and flag historical work."""
        raise NotImplementedError("Independent implementation required")
