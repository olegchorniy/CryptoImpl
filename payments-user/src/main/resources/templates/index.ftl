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
    <h1>FI-Cash</h1>
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
                <th>Outgoing session exist</th>
            </tr>
            </thead>
            <tbody>

                <#list broker.vendors as vendor>
                <tr>
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
<#else>
<div class="block"><h2 style="color: red">Broker unavailable</h2></div>
</#if>

<script src="/js/jquery-2.2.3.min.js"></script>
<script src="/js/render.js"></script>
<script src="/js/api.js"></script>
<script src="/js/pay-word.js"></script>
</body>
</html>