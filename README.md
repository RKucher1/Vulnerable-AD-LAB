Vulnerable AD lab environment configured with users, weak passwords and breadcrumbs to help teach basic Active Directory pentesting techniques.

**Usage**
- **Prereqs:** An Ubuntu-like host with `sudo` access, sufficient disk (~200–300 GB) and RAM (enough for the VMs you plan to run). The script will attempt to install `virtualbox`, `vagrant`, and `ansible` via `apt` if missing.
- **Run:**

```
chmod +x setup.sh
./setup.sh
```

- The script creates `vuln-credit-union-lab/`, writes a `Vagrantfile` and an `ansible/` layout, then brings up VMs sequentially (Domain Controller, File Server, multiple Windows 11 workstations, a Win7 legacy VM and a web server).

**Sanity check performed**
- You can run `bash -n setup.sh` to do a basic shell syntax check. I also corrected a mismatch so the generated `Vagrantfile` uses the same Windows 11 box that the script pre-checks (`gusztavvargadr/windows-11`).

**How to change how many computers are created**
The script currently generates 10 Windows 11 workstations. Because the script writes both the `Vagrantfile` and a static `ansible/inventory`, you must keep those two parts consistent when you change the count.

Two approaches:

- Quick manual edit (fast):
	- Edit `setup.sh` and change the Vagrant loop range from `(1..10).each do |i|` to `(1..N).each do |i|` where `N` is the desired count.
	- Update the `ansible/inventory` block written by the script so the `win11workstations` group lists only `w11-01`..`w11-0N`.

- Recommended (safer & repeatable): add a `W11_COUNT` variable and make the script generate both the Vagrantfile and inventory from that single value. Example (conceptual):

```
# Near the top of setup.sh
W11_COUNT=3

# Replace the static loop with a dynamic loop in the Vagrantfile heredoc
(1..W11_COUNT).each do |i|
	# generate w11 entries
end

# And generate inventory entries programmatically for w11-01..w11-$(printf '%02d' $W11_COUNT)
```

If you'd like, I can implement the `W11_COUNT` variable and update `setup.sh` so it automatically builds matching inventory — tell me the desired default and I'll patch and push it.

**Safety notes**
- This environment is intentionally insecure for training. Do not attach it to production or public networks.
- The script aborts if `vuln-credit-union-lab/` already exists to avoid accidental overwrites. Remove or move the directory if you want to re-run.

**Next steps I can take**
- Parameterize `setup.sh` with `W11_COUNT` and make inventory generation match (I can implement this and push the change).
- Reduce default VM memory/cpu values for lower-resource hosts.

If you want a small default lab (3–4 VMs) I can update the script now — tell me the preferred VM count.
