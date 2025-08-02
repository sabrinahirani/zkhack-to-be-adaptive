## zkHack Challenge #5  
*Challenge: https://www.zkhack.dev/events/puzzle5.html*  

### Relevant Background

#### Pedersen Commitments

A Pedersen commitment is a cryptographic primitive that allows a prover to commit to a value while keeping it hidden, and yet binding—meaning they cannot open the commitment to a different value later.

In a group $\mathbb{G}$ of prime order $q$ with two generators $G, H \in \mathbb{G}$ (with unknown discrete log relation), a Pedersen commitment to a value $a \in \mathbb{F}_q$ using randomness $r \in \mathbb{F}_q$ is:

$$
C = a \cdot G + r \cdot H
$$

This commitment scheme is perfectly hiding and computationally binding under the Discrete Logarithm (DLOG) assumption.

---

#### Fiat–Shamir Transform

The Fiat–Shamir transform allows a $\Sigma$-protocol to be made non-interactive by hashing the transcript to generate the challenge.

If the challenge is derived from all relevant public data—including commitments and instance data—the transform is secure in the random oracle model. If not, the prover may exploit this to mount an adaptive attack.

---

#### The Double Equality Protocol

The prover wishes to prove knowledge of a single value $a \in \mathbb{F}_q$ such that it is committed in two different Pedersen commitments:

- $C_1 = a \cdot G + r_1 \cdot H$
- $C_2 = a \cdot G + r_2 \cdot H$

To prove knowledge of $a$, the prover constructs a $\Sigma$-protocol as follows:

**Step \#1: Commitment Phase**

The prover samples random values $\rho, \tau \in \mathbb{F}_q$ and computes:

- $C_\rho = \rho \cdot H$  
- $C_\tau = \tau \cdot H$

These act as "commitments to randomness."

**Step \#2: Fiat–Shamir Challenge**

A challenge $e \in \mathbb{F}_q$ is computed using the Fiat–Shamir transform:

$$
e = \text{Hash}(\text{commitment key}, C_\rho, C_\tau)
$$

> **⚠️ Important:** The challenge does *not* include the commitments $C_1$ or $C_2$ in the hash. This makes the Fiat–Shamir transform **weak** and insecure.

**Step \#3: Response Computation**

Given a known secret $a$, the prover computes:

- $s = r + e \cdot a$
- $u = \rho + e \cdot r_1$
- $t = \tau + e \cdot r_2$

**Step \#4: Verification**

The verifier checks that:

- $s \cdot G + u \cdot H \stackrel{?}{=} C_\rho + e \cdot C_1$
- $s \cdot G + t \cdot H \stackrel{?}{=} C_\tau + e \cdot C_2$

---

### The Exploit

The Fiat–Shamir transform used here **does not include** the commitments $C_1$ and $C_2$ in the challenge hash, allowing the prover to choose these commitments *after* seeing the challenge $e$. This enables an adaptive attack.

### Exploiting Weak Fiat–Shamir

Suppose our goal is to construct two Pedersen commitments:

- $C_1 = a_1 \cdot G + r_1 \cdot H$
- $C_2 = a_2 \cdot G + r_2 \cdot H$

such that $a_1 \ne a_2$, but the proof still passes the verifier's checks.

We begin by observing the verification equations:

- $s \cdot G + u \cdot H \stackrel{?}{=} C_\rho + e \cdot C_1$
- $s \cdot G + t \cdot H \stackrel{?}{=} C_\tau + e \cdot C_2$

The values $C_\rho = r \cdot H + \rho \cdot H$ and $C_\tau = r \cdot H + \tau \cdot H$ are both used in computing the Fiat–Shamir challenge:

$$
e = \text{Hash}(C_\rho, C_\tau)
$$

Since the challenge $e$ depends on $C_\rho$ and $C_\tau$, these values must be fixed *before* the challenge is computed, and cannot be changed later.

That means we are **stuck with the values of $e$, $\rho$, and $\tau$** once the commitment phase is complete.

---

### Working Backwards

Let’s now examine the prover’s response computation:

- $s = r + e \cdot a$

However, we now want to allow *two different* messages $a_1$ and $a_2$ in commitments $C_1$ and $C_2$, while maintaining the same response value $s$. This implies:

$$
s = r + e \cdot a_1 = r + e \cdot a_2 + (\rho - \tau)
$$

This forces the following relationship between $a_1$ and $a_2$:

$$
a_2 = a_1 - \frac{\tau - \rho}{e}
$$

This key equation allows us to adaptively choose $a_2$ **after** the challenge $e$ is known.

---

#### Step-by-Step Attack

1. **Commit Randomness First:**
   - Choose two random values $\rho, \tau$.
   - Compute $C_\rho = \rho \cdot H$, $C_\tau = \tau \cdot H$.

2. **Compute Fiat–Shamir Challenge:**
   - Let $e = \text{Hash}(\text{commitment key}, C_\rho, C_\tau)$.

3. **Choose a First Secret Message:**
   - Pick $a_1 \in \mathbb{F}_q$ and a random $r_1$.
   - Compute $C_1 = a_1 \cdot G + r_1 \cdot H$.

4. **Compute Response:**
   - Let $s = \rho + e \cdot a_1$
   - Let $u = \rho + e \cdot r_1$

5. **Adaptively Choose a Different $a_2$:**

   Now solve for $a_2$ such that the second verification equation holds. Let $r_2$ be arbitrary, and compute:

   $$
   a_2 = a_1 - \frac{\tau - \rho}{e}
   $$

   Then compute $C_2 = a_2 \cdot G + r_2 \cdot H$

6. **Compute Final Responses:**
   - $t = \tau + e \cdot r_2$

7. **Output the full proof:**
   - The transcript passes both verification equations.
   - But $a_1 \ne a_2$, so the two commitments are to **different values**.

---

### Fix

To prevent this type of adaptive attack, we must use a **strong Fiat–Shamir transform**.

Change:

```rust
let challenge = hash(commitment_key, C_rho, C_tau);
```

To: 
```rust
let challenge = hash(commitment_key, C_rho, C_tau, C_1, C_2);
```

---

#### Commands

```rust
cargo run --bin verify-strong-adaptivity
```