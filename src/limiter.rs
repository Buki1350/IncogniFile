use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct Limiter(Mutex<HashMap<String, (Instant, u32)>>);

// login and register limiter based on RESET_TIME
impl Limiter {
    pub fn allow(&self, account: &str, register: bool) -> bool {
        const RESET_TIME: Duration = Duration::from_secs(900); // 15 min

        let Ok(mut entries) = self.0.lock() else {
            return false;
        };

        let now = Instant::now();
        // remove entries older than RESET_TIME
        entries.retain(|_, (start, _)| now.duration_since(*start) < RESET_TIME);

        let global = if register { "register" } else { "login" };
        let max = if register { 20 } else { 100 };
        let global_key = format!("global:{global}");
        if entries.get(&global_key).is_some_and(|(_, n)| *n >= max) {
            return false;
        }
        // 5 login attempts per account in RESET_TIME
        let account_key = format!("account:{account}");
        if !register && entries.get(&account_key).is_some_and(|(_, n)| *n >= 5) {
            return false;
        }

        // add or update entries
        entries.entry(global_key).or_insert((now, 0)).1 += 1;
        if !register {
            entries.entry(account_key).or_insert((now, 0)).1 += 1;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_and_global_budgets() {
        let l = Limiter::default();
        for _ in 0..5 {
            assert!(l.allow("alice", false));
        }
        assert!(!l.allow("alice", false));
        assert!(l.allow("bob", false));
        for _ in 0..20 {
            assert!(l.allow("", true));
        }
        assert!(!l.allow("", true));
    }
    #[test]
    fn concurrent_attempts_cannot_bypass_budget() {
        let l = std::sync::Arc::new(Limiter::default());
        let handles: Vec<_> = (0..30)
            .map(|_| {
                let l = l.clone();
                std::thread::spawn(move || l.allow("alice", false))
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap() as usize)
                .sum::<usize>(),
            5
        );
    }
}
