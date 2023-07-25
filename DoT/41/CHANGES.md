## Changes made

- File E041_chatlog_w_usernames_dot_change.py
    - Handles the accidental removal of tcp.dstport as bad feature and ensures all the DoT (inbound) traffic is captured.
- File E041_chatlog_w_usernames_with_isp.py
    - Same as above, but with addition of the Access_Resolver scope to the analysis. (Also adds a isp filter)
- File E041_chatlog_w_usernames_without_shadow.py
    - Tried to remove the shadow traffic from the analysis, but this includes the dot change made above. The chatlog being read are from the new server log from gns3 rather than from shadow. This resulted in a zero accuracy score.
- File E041_chatlog_w_usernames_without_shadow_with_isp.py
    - Same file as above, but with just Access_Resolver scope added to the analysis. (Also adds a isp filter). This resulted in a zero accuracy score as well.
- File E041_chatlog_w_usernames_dot_change_unscaled.py
    - This is the file which had scaling removed from it, and the dot change made above. This resulted in a zero accuracy score as well.