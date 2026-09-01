"""Factory for creating the plaform detection engine."""

from app.detection.engine import DetectionEngine
from app.detection.rules.directory_scanning import DirectoryScanningRule
from app.detection.rules.excessive_sudo import ExcessiveSudoRule
from app.detection.rules.new_user_creation import NewUserCreationRule
from app.detection.rules.sql_injection import SQLInjectionRule
from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.detection.rules.successful_after_failures import SuccessfulAfterFailuresRule
from app.detection.rules.suspicious_user_agent import SuspiciousUserAgentRule
from app.detection.rules.xss_attempt import XSSAttemptRule


def build_engine () -> DetectionEngine:
    """Create a engine with all eight detection rules."""

    engine = DetectionEngine()

    engine.register_rule(SSHBruteForceRule())
    engine.register_rule(SuccessfulAfterFailuresRule())
    engine.register_rule(ExcessiveSudoRule())
    engine.register_rule(NewUserCreationRule())
    engine.register_rule(DirectoryScanningRule())
    engine.register_rule(SQLInjectionRule())
    engine.register_rule(XSSAttemptRule())
    engine.register_rule(SuspiciousUserAgentRule())

    return engine