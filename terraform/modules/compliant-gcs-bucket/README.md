# List each control by NIST family

## SC-12

SC-12: cryptographic key establishment. We own the key, not Google.

SC-13 / SC-28: SC-13 / SC-28: cryptographic protection at rest. 90-day rotation.

* SC-28: Protection of information at rest.
AES-256 keeps this lab simple. The commented block below shows how you'd # switch to KMS-managed keys, covered in a later lab.

AU-11 AC-3 + SC-28 + CM-6 + AU-11 in one resource declaration.

* AC-3: Access control, explicit deny on every public access vector.

* AU-3 / AU-6: Content of audit records + audit review.

CM-6

* CM-6: Configuration settings, required compliance tags applied to every taggable resource by default. Removes the chance of forgetting them

* CM-6: Versioning preserves prior object states for recovery and audit.
