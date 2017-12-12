<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>FI-Cash</title>
    <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
    <link rel="stylesheet" href="/pay-word.css">
</head>
<body>

<div class="header block">
    <h1><a href="/">FI-Cash</a></h1>
</div>

<#if broker??>
<div class="block">
    <h3 class="title">Broker: <a href="${broker.address}">${broker.name} (${broker.address})</a></h3>

    <div class="body">
        <button id="register-button">Register</button>
    </div>

    <#if user??>
        <div class="body">
            <table class="summary">
                <tbody>
                <tr>
                    <td>ID</td>
                    <td>${user.id}</td>
                </tr>
                <tr>
                    <td>Name</td>
                    <td>${user.name}</td>
                </tr>
                <tr>
                    <td>Balance</td>
                    <td>${user.balance}</td>
                </tr>
                </tbody>
            </table>
        </div>
    </#if>
</div>

<div class="block">
    <h3 class="title">Vendors</h3>
    <div class="body">
        <table class="vendors">
            <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Address</th>
                <th>Registration date</th>
                <th>Session opened</th>
            </tr>
            </thead>
            <tbody>

                <#list broker.vendors as vendor>
                <tr class="js-vendor" data-vendor-id="${vendor.id}">
                    <td>${vendor.id}</td>
                    <td>${vendor.name}</td>
                    <td><a href="${vendor.address}">${vendor.address}</a></td>
                    <td>${vendor.registrationDate}</td>

                    <#assign color>
                        <#if vendor.outgoingSessionId??>green<#else>red</#if>
                    </#assign>

                    <td style="background: ${color}; width: 15px"></td>
                </tr>
                </#list>
            </tbody>
        </table>
    </div>
</div>

    <#if recipient??>
    <div class="block">
        <h3 class="title">Payments <span
                style="font-weight: normal;">(${recipient.name} - ${recipient.address})</span>
        </h3>

        <div class="body payments">
            <p>
                <button id="start-session-button" data-recipient-id="${recipient.id}">Send commitment</button>
            </p>

            <#if recipient.session??>
                <div>
                    <table class="summary">
                        <tbody>
                        <tr>
                            <td>Session ID</td>
                            <td>${recipient.session.sessionId}</td>
                        </tr>
                        <tr>
                            <td>Transferred funds</td>
                            <td>${recipient.session.transferredAmount}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>

                <div style="margin-top: 20px">
                    <div class="column">
                        <h4>Coins</h4>
                        <ul class="coins">
                            <#list recipient.session.paywords as payword>
                                <li class="<#if payword.paid>spent</#if>">${payword.hash}</li>
                            </#list>
                        </ul>
                    </div>

                    <div class="column">
                        <h4>Transfer funds</h4>
                        <input placeholder="Amount" id="transfer-amount">
                        <button id="transfer-funds" data-session-id="${recipient.session.sessionId}">Transfer</button>
                    </div>

                    <div style="clear: both"></div>
                </div>
            </#if>
        </div>
    </div>
    </#if>

<div class="block">
    <h3 class="title">Incoming payments</h3>

    <div class="body">
        <table class="incoming">
            <thead>
            <tr>
                <th>User</th>
                <th>Session ID</th>
                <th>Amount</th>
                <th>Root</th>
                <th>Actions</th>
            </tr>
            </thead>
            <tbody>
                <#list incomingSessions as session>
                <tr>
                    <td>${session.sender.name} <#--- ${session.sender.address}--></td>
                    <td>${session.sessionId}</td>
                    <td>${session.amount}</td>
                    <td>${session.root}</td>
                    <td>
                        <button class="js-finish-session" data-session-id="${session.sessionId}">Finish session</button>
                    </td>
                </tr>
                </#list>
            </tbody>
        </table>
    </div>

    <div class="body">
        <table class="test"></table>
    </div>
</div>

<#else>
<div class="block"><h2 style="color: red">Broker unavailable</h2></div>
</#if>

<script src="/js/jquery-2.2.3.min.js"></script>
<script src="/js/render.js"></script>
<script src="/js/api.js"></script>
<script src="/js/pay-word.js"></script>
</body>
</html>