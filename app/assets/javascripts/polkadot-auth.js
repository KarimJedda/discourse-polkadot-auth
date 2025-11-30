import { web3Accounts, web3Enable, web3FromSource } from 'https://cdn.jsdelivr.net/npm/@polkadot/extension-dapp/+esm';
import { stringToHex } from 'https://cdn.jsdelivr.net/npm/@polkadot/util/+esm';

let allAccounts = [];
let selectedAccount = null;

async function enableWallet() {
    const allInjected = await web3Enable('Discourse Polkadot Auth');
    if (!allInjected.length) {
        alert("No extension found. Please install Polkadot.js extension.");
        return;
    }

    allAccounts = await web3Accounts();
    if (!allAccounts.length) {
        alert("No accounts found. Please add an account in the extension.");
        return;
    }

    const accountsDropdown = document.getElementById('accounts');
    accountsDropdown.innerHTML = '';
    allAccounts.forEach(account => {
        const option = document.createElement('option');
        option.value = account.address;
        option.textContent = `${account.meta.name} (${account.address})`;
        accountsDropdown.appendChild(option);
    });
    document.getElementById('account-section').style.display = 'block';
}

function selectAccount() {
    selectedAccount = allAccounts.find(acc => acc.address === document.getElementById('accounts').value);
    document.getElementById('selected-account').textContent = `Selected Account: ${selectedAccount.address}`;
    document.getElementById('sign-section').style.display = 'block';
}

async function signChallenge() {
    if (!selectedAccount) {
        alert("Please select an account first.");
        return;
    }

    const challenge = document.getElementById('challenge').value;
    const injector = await web3FromSource(selectedAccount.meta.source);
    const signRaw = injector?.signer?.signRaw;

    if (!!signRaw) {
        try {
            const { signature } = await signRaw({
                address: selectedAccount.address,
                data: stringToHex(challenge),
                type: 'bytes'
            });
            
            // Submit the signature
            document.getElementById('signature').value = signature;
            document.getElementById('polkadot-form').submit();
        } catch (error) {
            alert(`Signing failed: ${error.message}`);
        }
    } else {
        alert("Signing not available.");
    }
}

// Set up event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('connect-wallet-btn').addEventListener('click', enableWallet);
    document.getElementById('accounts').addEventListener('change', selectAccount);
    document.getElementById('sign-challenge-btn').addEventListener('click', signChallenge);
});
