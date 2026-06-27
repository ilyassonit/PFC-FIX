-- ============================================================
-- Migrations SQL pour les corrections de bugs
-- Appliquer ces requêtes dans votre base MySQL (database: presence)
-- ============================================================

-- --------------------------------------------------------
-- 1) Ajouter les colonnes de temps à la table seances
--    (Bug 4: Permet de saisir l'heure de début et de fin)
-- --------------------------------------------------------
ALTER TABLE seances
    ADD COLUMN heure_debut TIME NULL AFTER date_seance,
    ADD COLUMN heure_fin   TIME NULL AFTER heure_debut;

-- --------------------------------------------------------
-- 2) S'assurer que justificatif_valide supporte les valeurs:
--    0 = en attente, 1 = validé, 2 = rejeté
--    (Bug 2: Permet de distinguer les justificatifs rejetés)
-- --------------------------------------------------------
ALTER TABLE presences
    MODIFY COLUMN justificatif_valide TINYINT NULL DEFAULT NULL;

-- --------------------------------------------------------
-- 3) (Optionnel) Mettre à jour les justificatifs existants
--    avec une valeur explicite pour éviter toute ambiguïté
-- --------------------------------------------------------
-- Marquer les justificatifs existants sans statut comme "en attente" (0)
UPDATE presences
SET justificatif_valide = 0
WHERE justificatif IS NOT NULL
  AND justificatif_valide IS NULL;
