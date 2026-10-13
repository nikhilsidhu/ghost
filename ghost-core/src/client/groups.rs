//! The groups this device holds: one per channel with a group of its own (a server's
//! default channel, a private channel), with the lookups that go with them kept in step:
//! the server each channel is in, and the channel each group's mailbox belongs to.

use std::collections::{HashMap, HashSet};

use crate::mls::group::GhostGroup;
use crate::wire::mls_group_mailbox_id;

#[derive(Default)]
pub(super) struct Groups {
    by_channel: HashMap<[u8; 32], GhostGroup>,
    /// Every channel listed, with its server; a channel stays listed while its group is
    /// taken out.
    server_of_channel: HashMap<[u8; 32], [u8; 32]>,
    channel_of_mailbox: HashMap<[u8; 32], [u8; 32]>,
}

impl Groups {
    /// Hold `group` as `channel_id`'s, in `server_id`. One held for the channel before is
    /// handed back, its mailbox forgotten.
    pub(super) fn insert(&mut self, channel_id: [u8; 32], server_id: [u8; 32], group: GhostGroup) -> Option<GhostGroup> {
        let before = self.by_channel.remove(&channel_id);
        if let Some(before) = &before {
            self.channel_of_mailbox.remove(&mls_group_mailbox_id(before.group_id()));
        }
        self.channel_of_mailbox.insert(mls_group_mailbox_id(group.group_id()), channel_id);
        self.server_of_channel.insert(channel_id, server_id);
        self.by_channel.insert(channel_id, group);
        before
    }

    /// A new group for a channel already listed, in the same server: what a rejoin or a
    /// reload makes, or a group taken out coming back.
    pub(super) fn replace(&mut self, channel_id: &[u8; 32], group: GhostGroup) -> Option<GhostGroup> {
        let server_id = self.server_of_channel.get(channel_id).copied().expect("the channel is listed");
        self.insert(*channel_id, server_id, group)
    }

    /// Forget a channel's group and everything listed for it.
    pub(super) fn remove(&mut self, channel_id: &[u8; 32]) -> Option<GhostGroup> {
        self.server_of_channel.remove(channel_id);
        let group = self.by_channel.remove(channel_id)?;
        self.channel_of_mailbox.remove(&mls_group_mailbox_id(group.group_id()));
        Some(group)
    }

    /// Take a channel's group out to work on it beside the rest of the client, leaving
    /// the channel listed; `replace` puts it back.
    pub(super) fn take(&mut self, channel_id: &[u8; 32]) -> Option<GhostGroup> {
        self.by_channel.remove(channel_id)
    }

    pub(super) fn get(&self, channel_id: &[u8; 32]) -> Option<&GhostGroup> {
        self.by_channel.get(channel_id)
    }

    pub(super) fn get_mut(&mut self, channel_id: &[u8; 32]) -> Option<&mut GhostGroup> {
        self.by_channel.get_mut(channel_id)
    }

    /// Whether a channel's group is held.
    pub(super) fn contains(&self, channel_id: &[u8; 32]) -> bool {
        self.by_channel.contains_key(channel_id)
    }

    pub(super) fn server_of(&self, channel_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.server_of_channel.get(channel_id).copied()
    }

    pub(super) fn channel_of_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.channel_of_mailbox.get(mailbox_id).copied()
    }

    /// Every group held, with its channel.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &GhostGroup)> {
        self.by_channel.iter()
    }

    pub(super) fn channel_ids(&self) -> Vec<[u8; 32]> {
        self.by_channel.keys().copied().collect()
    }

    /// The channels listed in a server.
    pub(super) fn channels_of<'a>(&'a self, server_id: &'a [u8; 32]) -> impl Iterator<Item = [u8; 32]> + 'a {
        self.server_of_channel.iter().filter(move |(_, s)| *s == server_id).map(|(c, _)| *c)
    }

    /// Every server with a channel listed.
    pub(super) fn servers(&self) -> HashSet<[u8; 32]> {
        self.server_of_channel.values().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::GhostProvider;
    use crate::identity::Identity;

    const SERVER: [u8; 32] = [1; 32];
    const CHANNEL: [u8; 32] = [2; 32];

    /// A group for the one channel; each in a storage of its own, as two for one channel
    /// cannot share one.
    fn group(identity: &Identity) -> GhostGroup {
        let provider = GhostProvider::new_in_memory().unwrap();
        GhostGroup::create(&provider, identity, &SERVER, &CHANNEL, Some(&[0x7E; 32]), None).unwrap()
    }

    #[test]
    fn a_group_is_found_by_channel_and_mailbox_and_server_until_removed() {
        let identity = Identity::generate().unwrap();
        let mut groups = Groups::default();
        let mailbox = mls_group_mailbox_id(group(&identity).group_id());

        assert!(groups.insert(CHANNEL, SERVER, group(&identity)).is_none());
        assert!(groups.contains(&CHANNEL));
        assert_eq!(groups.server_of(&CHANNEL), Some(SERVER));
        assert_eq!(groups.channel_of_mailbox(&mailbox), Some(CHANNEL));
        assert_eq!(groups.channels_of(&SERVER).collect::<Vec<_>>(), vec![CHANNEL]);
        assert_eq!(groups.servers(), HashSet::from([SERVER]));

        assert!(groups.remove(&CHANNEL).is_some());
        assert!(!groups.contains(&CHANNEL) && groups.get(&CHANNEL).is_none());
        assert_eq!(groups.server_of(&CHANNEL), None);
        assert_eq!(groups.channel_of_mailbox(&mailbox), None);
        assert!(groups.servers().is_empty() && groups.channel_ids().is_empty());
    }

    #[test]
    fn a_group_taken_out_leaves_its_channel_listed_until_it_is_back() {
        let identity = Identity::generate().unwrap();
        let mut groups = Groups::default();
        groups.insert(CHANNEL, SERVER, group(&identity));
        let mailbox = mls_group_mailbox_id(groups.get(&CHANNEL).unwrap().group_id());

        let taken = groups.take(&CHANNEL).expect("held");
        assert!(!groups.contains(&CHANNEL), "out");
        assert_eq!(groups.server_of(&CHANNEL), Some(SERVER), "still listed");
        assert_eq!(groups.channel_of_mailbox(&mailbox), Some(CHANNEL));

        assert!(groups.replace(&CHANNEL, taken).is_none(), "nothing was in its place");
        assert!(groups.contains(&CHANNEL));
        assert!(groups.replace(&CHANNEL, group(&identity)).is_some(), "a rejoin hands the old group back");
        assert_eq!(groups.channel_of_mailbox(&mailbox), Some(CHANNEL));
    }
}
