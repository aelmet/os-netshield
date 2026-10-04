# Prompt: build "Blade & Crown" (3D battle chess) in Unity

Copy everything below the line into your local model. If its context window is small, give it one PHASE at a time, and paste back the files it already wrote before asking for the next phase.

---

You are an expert Unity developer (Unity 2022.3 LTS or newer, C#, Universal Render Pipeline). Build a complete, playable 3D chess game called **Blade & Crown**, inspired by the 1988 game *Battle Chess*: every capture plays out as an animated fight between the two pieces. Do not copy any original Battle Chess art, names or sounds; create original work in that spirit.

## Rules for how you work
- Write complete C# files, never fragments or "..." placeholders. Every file must compile.
- Put each class in its own file under `Assets/Scripts/<Folder>/`. Tell me the exact path of every file.
- Use only Unity built-ins plus free packages from the Unity Package Manager (Cinemachine and TextMeshPro are allowed). No paid assets.
- Keep game logic (chess rules, AI) in plain C# classes with no `MonoBehaviour`, so it can be unit-tested.
- After each phase, list exactly what I must do in the Unity Editor: create scenes and prefabs, assign fields in the Inspector, set tags and layers. Number the steps.
- If something is ambiguous, choose the simplest option that matches this spec and say what you chose.

## Overall design
- **Board:** 8×8, square size 1 unit, centred at the origin. a1 is at (−3.5, 0, 3.5); files run along +X and ranks along −Z. Light squares are yellow-green marble (#BDB54A), dark squares near-black marble (#15180F). Add a dark wooden frame with a gold inner trim, and file/rank labels in gold.
- **Sides:** "Blue" (moves first, bottom, robes #2C44C8) and "Red" (top, robes #D23A6E, a pink-red as in the classic game). Every piece stands on a glowing disc in its team colour.
- **Camera:** orbit camera. Drag to rotate, scroll or pinch to zoom, Reset View button. During a fight, Cinemachine blends to a close-up side camera; afterwards it blends back.
- **UI (TextMeshPro):** title, a status pill ("Blue to move", "Red is plotting…", "Check", "Checkmate · Blue wins"), captured pieces per side with material advantage (+3). Buttons: New game, Undo, Opponent (Computer / Two players), Level (Squire / Knight / Warlord), Battles on/off (default ON, regardless of any reduced-motion setting), Sound on/off, Reset view. Add a promotion picker (Queen, Rook, Bishop, Knight) and a game-over panel. Flash "CHECK", "CHECKMATE" and "PROMOTED" banners.

## PHASE 1: Chess engine (pure C#, no Unity types)
Files: `Chess/Piece.cs`, `Chess/Move.cs`, `Chess/GameState.cs`, `Chess/MoveGenerator.cs`, `Chess/Ai.cs`.
- Board is `Piece?[64]`, index = rank*8 + file, rank 0 = Blue's back rank. Each piece has a type (P N B R Q K), a colour, and a unique `int Id` that is kept through promotion (so its 3D model can be found again).
- `GameState`: board, side to move, castling rights (4 flags), en-passant square (−1 if none), half-move clock, and captured-piece lists per side. `Make(Move)` returns a NEW state (immutable), so undo is just a history stack.
- `Move`: from, to, capture square (−1 if none; differs from `to` for en passant), promotion type, castle side, double-pawn-push flag.
- Full legal move generation: all piece moves, double pawn push, en passant, promotion to all four pieces, and castling both sides. Castling needs: rights still held, king and rook unmoved, squares between empty, king not in check, and king not passing through or landing on an attacked square. Rights are lost when the king or rook moves or a rook is captured on its home square. Filter out moves that leave your own king in check.
- Game end: checkmate, stalemate, fifty-move rule, and insufficient material (kings only, or a king plus a single bishop or knight).
- **Verify with perft tests** (write them as Unity Test Framework edit-mode tests): start position depth 1–4 = 20, 400, 8902, 197281. "Kiwipete" `r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq -` depth 1–3 = 48, 2039, 97862. Position 3 `8/2p5/3p4/KP5r/1R3p1k/8/4P1P1/8 w - -` depth 1–4 = 14, 191, 2812, 43238. Include a FEN parser for the tests. Do not continue to Phase 2 until these pass.
- AI: negamax with alpha-beta pruning. Order captures first (most valuable victim, least valuable attacker). Material values P100 N320 B330 R500 Q900. Add a small centre bonus for knights and bishops, a pawn-advance bonus, and a king-safety penalty for a centralised king. Mate score is −(100000 + depth) so faster mates are preferred. Add a few points of random noise at the root so games vary. Depths: Squire 1, Knight 2, Warlord 4. Run the search on a background thread (`Task.Run`) and apply the move on the main thread.

## PHASE 2: Board, pieces and input
Files: `View/BoardView.cs`, `View/PieceView.cs`, `View/PieceFactory.cs`, `Input/BoardInput.cs`, `Game/GameController.cs`, `UI/HudController.cs`.
- `GameController` owns the `GameState`, the history, mode, AI level and the "busy" flag (no input while animating or thinking). It calls the battle director for every move and waits for it to finish (use coroutines or async/await with UniTask, your choice; be consistent).
- Click a piece of the side to move: it raises a guard stance, and legal targets show gold dots (moves) or red rings (captures). Highlight the last move in light blue and a checked king's square in red. Raycast against piece colliders and board squares.
- Pieces face the enemy (Blue faces −Z, Red faces +Z) and turn back to face the enemy after every move.
- Walking: turn toward the target, play a walk loop (run for 3+ squares), then go back to idle. Knights leap in an arc. Castling: the king walks, then the rook jumps over to its square. Promotion: a golden burst, then the new piece scales up from zero.

## PHASE 3: Characters (realistic human proportions, NOT chibi)
Use ONE humanoid rig for every piece. Recommended: a free Mixamo character plus Mixamo animations, or the free "KayKit Adventurers" pack (CC0) whose skeleton has idle/walk/run/1H and 2H attacks/block/hit/death/spellcast/kick/cheer clips. Set up a Mecanim Animator Controller with an `Idle` loop, a `Walk`/`Run` blend, a `Guard` loop, and one-shot trigger states: `Attack1`, `Attack2`, `Stab`, `Chop`, `SpinSlash`, `Kick`, `Punch`, `CastShoot`, `CastLong`, `CastRaise`, `Block`, `HitA`, `HitB`, `DeathA`, `DeathB`, `JumpShort`, `Cheer`. If the source characters are chibi, scale the leg bones ×1.8, arm bones ×1.3 and head ×0.65 using an `AnimationRigging` setup or a `LateUpdate` bone post-process, so figures look like tall, slim adults (head about 1/8 of total height).

Dress each type with attached meshes (child objects of bones). Use team colours via a shared material with a `_TeamColor` property (MaterialPropertyBlock):
- **Pawn:** foot soldier. Kettle helmet with brim, chainmail shirt, team-colour tabard and short skirt, leather belt and boots, sword and round shield. Height 0.84.
- **Knight:** full plate armour, closed great helm with eye slit and a team-colour plume, tabard with a gold cross, long cape, sword and heraldic shield. Height 0.95.
- **Bishop / Wizard:** floor-length robe, white over-robe, gold stole, tall white mitre with gold band and cross, white beard, crystal-topped staff with a glowing tip (gold-white for Blue; purple "warlock" for Red). Height 1.0.
- **Queen / Sorceress:** flowing floor-length gown with gold hem and waist band, light puffed sleeves, long hair (golden for Blue, dark brown for Red), gold crown with jewels, necklace, long cape, sceptre/wand with a glowing orb. Height 1.0.
- **King:** royal robe with gold belt, ermine collar (white with black spots), long cape, big white beard and moustache, large gold crown with a velvet cap, jewels and a cross, sword and shield. Height 1.08.
- **Rook (transforming):** at rest it is a stone castle tower (crenellations, door, two glowing windows, a team-colour flag). Whenever it moves or fights it TRANSFORMS: the tower rumbles, cracks and sinks while a hulking "stone man" made of rough faceted rocks with glowing eyes and a small crenellated crown rises up (orange stone for Red, slate blue-grey for Blue). It changes back into a tower after the move. A transform takes 0.7 s, with dust, bouncing rock chunks and camera shake.

## PHASE 4: Battle director (the heart of the game)
File: `Battle/BattleDirector.cs`, plus `Battle/Spells.cs`, `Battle/Deaths.cs`, `Battle/Specials.cs`, `Fx/Particles.cs`, `Fx/Sfx.cs`.
On every capture (when Battles is on):
1. **Camera and clarity:** fade every other piece to 15% opacity so nothing blocks the view, and blend to a close-up side camera aimed at the midpoint of the two fighters.
2. Both pieces transform if they are rooks. The attacker walks to its reach distance (pawn 0.85, knight 0.95, bishop 1.0, stone man 0.9, king 0.95, queen 1.5 because she casts from range). The defender turns to face it.
3. **Exchange:** the attacker plays an opening blow and the defender BLOCKS (metal clang, sparks, small knock-back). Then the defender counter-attacks with its own opening move and the attacker blocks. Pieces of the same type trade two exchanges. Mages (bishop, queen) block with a translucent magic bubble shield instead of a weapon.
4. **Finisher:** pick a matchup special if one applies (table below), otherwise pick randomly from the attacker's finishers.
5. Remove the victim, the attacker walks onto the square (pawns cheer first), the camera returns, and other pieces fade back in.

Impact timing: trigger the defender's reaction at about 45% of a melee clip (55% for spell clips), or use Animation Events.

**Arsenal (opening blows / finishers):**
- Pawn: stab, chop / slice (→ falls back), stab (→ falls forward).
- Knight: diagonal slice, chop / horizontal slash (→ DeathB), spin slash (→ DeathA).
- Bishop: magic missile, staff chop / sky lightning, holy beam, fireball.
- Stone man (rook): punch A, punch B / leaping body-slam that flattens the victim.
- Queen: magic missile / fireball, frost shards, sky lightning.
- King: chop, diagonal slice / stab then a royal kick that launches the enemy flying (2 times in 3), or sky lightning (1 in 3).

**Spells (side-coloured: Blue fire is orange, Red "warlock" fire is green; Blue lightning is pale blue, Red is purple):**
- Magic missile: a glowing orb arcs from the staff/wand tip with a particle trail and a point light.
- Fireball: a larger orb, then an explosion and screen shake. The victim **burns**: tints to charcoal with an orange emissive glow, shrinks and smokes away.
- Sky lightning: a jagged bolt (LineRenderer, 9 zig-zag segments) strikes from 6 units above, flickering 3 times with a bright flash and thunder. The victim is **zapped**: flash white, darken, DeathA, smoke.
- Frost: six ice shards fly in a stream. The victim **freezes** (animation stops, tints icy blue) and then **shatters** into bouncing ice chunks.
- Holy beam: a translucent additive light column descends. The victim **lifts** upward, fading in sparkles.

**Victim overrides:** a stone man always **crumbles** into bouncing rocks (except when squashed or frozen). A queen hit by a melee finisher fades away in her own sparkles.

**Matchup specials (comic, in the spirit of 1988):**
| Attacker vs victim | Special | Chance |
|---|---|---|
| Knight vs Knight | "Black Knight": the victim's shield arm is chopped off and tumbles away (speech bubble "Only a scratch!"), he kicks back, loses his sword arm ("I've had worse!"), kicks again, and finally dies to a horizontal slash. | 100% |
| Rook vs P/N/B/Q | **Gobble**: the stone man punches, lifts the victim to its mouth, the victim shrinks into it with three crunches ("Crunch!"), then it spits out bouncing armour bits. | 60% |
| Queen vs Pawn / Knight / Bishop | **Frog curse**: a green swirl, a puff of smoke, the victim becomes a small frog that hops away three times ("Ribbit!") and vanishes. | 70% / 40% / 30% |
| Bishop vs Knight/Pawn, Knight vs Pawn/Bishop, King vs Pawn | **Sliced in half**: freeze, then the upper body (spine and above) slides off and tumbles, and the legs topple a moment later ("Sliced!"). | 50% / 30% / 25% |

To cut off limbs or halve a body: collect the renderers under the chosen bones, copy them into a new GameObject at the same world pose, give it a Rigidbody with an impulse and torque, hide the originals, and destroy the copy after 2.5 s with a fade. Speech bubbles are a world-space or screen-space TMP panel that shows for 1.5 s.

**Juice:** a particle burst helper (sparks, dust, smoke, magic, ice, rocks with physics bounce), camera shake, a red hit-flash using emissive, knock-back nudges.
**Sound:** generate simple procedural sounds (OnAudioFilterRead or pre-baked AudioClips from code) for clang, whoosh, thud, crush, zap, charge, step, select, check fanfare and ribbit. Sound starts muted until the first click.

## PHASE 5: Polish and safety
- If any battle coroutine throws, catch it, put the board back in a consistent state (remove the victim, place the attacker on its square, restore opacity, reset the camera) and continue the game. Never freeze.
- Undo: in Computer mode, undo two plies back to the player's turn. Rebuild all piece views from the state.
- Performance: object-pool particles, keep under 300 draw calls (GPU instancing on board squares).
- Build targets: Windows/macOS standalone and Android. On mobile: touch orbit, pinch zoom, and a UI layout that works in portrait at 400 px wide.
- Write a `README.md` explaining controls, scene setup and the asset licences (credit KayKit or Mixamo as appropriate).

Start with PHASE 1 now.
