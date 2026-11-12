-- The shop's billing database: the invoices the bookkeeper works from and the payment provider's keys.
CREATE DATABASE billing DEFAULT CHARACTER SET utf8mb4;
CREATE TABLE billing.payment_providers (
  provider    varchar(32) PRIMARY KEY,
  secret_key  varchar(128) NOT NULL,
  key_rotated date,
  note        varchar(128)
) ENGINE=InnoDB;
INSERT INTO billing.payment_providers VALUES
  ('stripe', 'sk_live_rotate_me', '2026-09-14', 'live key; the payout job on web-01 uses it'),
  ('cash',   'n/a',               NULL,         'counter sales, no key');
CREATE TABLE billing.invoices (
  id        int AUTO_INCREMENT PRIMARY KEY,
  customer  varchar(64) NOT NULL,
  cents     int NOT NULL,
  issued_at date NOT NULL,
  paid_at   date
) ENGINE=InnoDB;
INSERT INTO billing.invoices (customer, cents, issued_at, paid_at) VALUES
  ('Blue Ridge Parkway Tours', 148000, '2026-08-02', '2026-08-19'),
  ('Hot Springs Resort',        39500, '2026-08-14', '2026-09-01'),
  ('Madison County Schools',   212000, '2026-09-03', '2026-09-25'),
  ('French Broad Outfitters',   67500, '2026-09-19', NULL),
  ('Asheville Ride Club',       24000, '2026-10-01', NULL),
  ('Laurel Valley Camp',       103000, '2026-10-12', NULL),
  ('Walnut Gap Farm Stay',      18500, '2026-10-21', NULL);
