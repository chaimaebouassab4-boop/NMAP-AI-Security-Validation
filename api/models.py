"""
API Data Models
===============
Pydantic models for request/response validation.
Version alignée avec l'orchestrateur, le validator local et les agents.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ValidationStatus(str, Enum):
    """Statut de validation possible"""
    VALID = "valid"
    INVALID = "invalid"
    REPAIRABLE = "repairable"


class ValidationIssue(BaseModel):
    """Représente un problème détecté lors de la validation"""
    type: str = Field(..., description="Type d'erreur (ex: permission_denied, syntax_error)")
    severity: str = Field(..., description="Niveau de gravité: low, medium, high, critical")
    message: str = Field(..., description="Description détaillée du problème")
    suggestion: Optional[str] = Field(None, description="Suggestion de correction")


class ValidationResult(BaseModel):
    """Résultat complet de la validation (local ou distant)"""
    status: ValidationStatus = Field(..., description="Statut final: valid, invalid, repairable")
    command: str = Field(..., description="Commande analysée")
    valid: bool = Field(..., description="True si la commande est exécutable sans risque majeur")
    risk_score: int = Field(..., ge=0, le=100, description="Score de risque (0 = sûr, 100 = très risqué)")
    risk_level: str = Field(..., description="Niveau de risque: low, medium, high, critical")
    issues: List[ValidationIssue] = Field(default_factory=list, description="Liste des problèmes bloquants")
    warnings: List[str] = Field(default_factory=list, description="Avertissements non bloquants")
    recommendation: str = Field(..., description="Recommandation globale")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    # Méthode pour compatibilité avec l'ancien code (si besoin)
    @property
    def score(self) -> float:
        """
        Compatibilité : certains agents attendent un score de confiance (0.0 à 1.0)
        On convertit le risk_score inversé : plus le risk est bas → plus la confiance est haute
        """
        return max(0.0, min(1.0, 1.0 - (self.risk_score / 100.0)))


class CommandCandidate(BaseModel):
    """Candidat de commande généré ou modifié par un agent"""
    command: str = Field(..., description="Commande Nmap proposée")
    user_id: Optional[str] = Field(None, description="Identifiant utilisateur")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Contexte supplémentaire")
    
    # Métadonnées des agents
    rationale: Optional[str] = Field(None, description="Explication de la génération/modification")
    source_agent: Optional[str] = Field(None, description="Nom de l'agent source (rag, llm, diffusion, selfcorr)")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confiance du générateur (échelle 0-1 parfois utilisée)")
    
    # Guidance pour les agents de génération
    suggested_generation: Optional[str] = Field(None, description="Stratégie suggérée (ex: 'Diffusion')")
    generation_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Métadonnées pour ajuster la génération")


class UserQuery(BaseModel):
    """Requête initiale de l'utilisateur"""
    user_id: Optional[str] = Field(None, description="Identifiant utilisateur optionnel")
    query: str = Field(..., description="Texte brut de la requête utilisateur")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Métadonnées additionnelles")


class FinalDecision(BaseModel):
    """Décision finale renvoyée à l'utilisateur"""
    command: str = Field(..., description="Commande finale validée et sûre")
    confidence: float = Field(..., ge=0.0, le=10.0, description="Confiance finale (échelle ajustée)")
    flags_explanation: Dict[str, str] = Field(default_factory=dict, description="Explication des flags utilisés")
    rationale: Optional[str] = Field(None, description="Explication complète du raisonnement")
    source_agent: Optional[str] = Field(None, description="Agent qui a produit la commande finale")
    validation_summary: Optional[str] = Field(None, description="Résumé de la validation finale")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class BatchValidationRequest(BaseModel):
    """Requête pour validation par lot"""
    commands: List[str] = Field(..., min_items=1, description="Liste de commandes à valider")


class BatchValidationResponse(BaseModel):
    """Réponse pour validation par lot"""
    total: int = Field(..., description="Nombre total de commandes")
    valid: int = Field(..., description="Nombre de commandes valides")
    invalid: int = Field(..., description="Nombre de commandes invalides")
    high_risk: int = Field(..., description="Nombre de commandes à haut risque")
    results: List[ValidationResult] = Field(..., description="Résultats détaillés")


class HealthResponse(BaseModel):
    """Réponse du health check"""
    status: str = "healthy"
    version: str = "2.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    uptime: Optional[float] = None
    active_agents: Optional[List[str]] = None