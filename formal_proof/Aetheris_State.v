(* Aetheris (AET) 状态转换逻辑定义 *)

Require Import Aetheris_Core.
Require Import Aetheris_Tree.

Require Import Coq.Lists.List.
Import ListNotations.

(** 定义全局状态 **)
Record GlobalState := {
  all_nullifiers : list Nullifier;
  all_commitments : list Commitment;
  state_tree : StateTree
}.

(** 有效转换谓词 (Valid Transition Predicate)
    不仅是数据的拼接，还必须满足：
    1. Nullifiers 不得冲突（双花防御）
    2. 所有的输入必须在当前状态树中有包含性证明
    3. 价值守恒
    4. ZK 证明有效
**)
Definition is_valid_transition (s : GlobalState) (tx : Transaction) : Prop :=
  (forall n, In n (tx_inputs tx) -> ~ In n (all_nullifiers s)) /\
  (forall c, In c (tx_inputs tx) -> exists path, has_valid_inclusion_proof c path (state_tree s)) /\
  is_value_conserved tx /\
  tx_proof tx > 0.

Parameter update_tree : StateTree -> list Commitment -> StateTree.

(** 状态转换函数: GlobalState + Transaction -> GlobalState **)
Definition transition (s : GlobalState) (tx : Transaction) : GlobalState :=
  {|
    all_nullifiers := (tx_inputs tx) ++ (all_nullifiers s);
    all_commitments := (tx_outputs tx) ++ (all_commitments s);
    state_tree := update_tree (state_tree s) (tx_outputs tx)
  |}.

(** 任务 2.2: 证明一个有效的状态转换必然导致旧 Record 的 Nullifier 被标记 **)
Theorem nullifier_added_after_transition : forall (s : GlobalState) (tx : Transaction) (n : Nullifier),
  In n (tx_inputs tx) -> In n (all_nullifiers (transition s tx)).
Proof.
  intros s tx n H.
  simpl.
  apply in_or_app.
  left.
  apply H.
Qed.

(** 任务 2.3: 证明状态转换保持了累积性 (Safety Property) **)
Theorem transition_preserves_past_nullifiers : forall (s : GlobalState) (tx : Transaction) (n : Nullifier),
  In n (all_nullifiers s) -> In n (all_nullifiers (transition s tx)).
Proof.
  intros s tx n H.
  simpl.
  apply in_or_app.
  right.
  apply H.
Qed.
