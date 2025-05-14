### 1. CloudFront with WAF for ROSA Workloads

``` mermaid

flowchart LR
    Users((Internet Users)) --> CloudFront[Amazon CloudFront]
    WAF[AWS WAF] --> |Protects| CloudFront
    CloudFront --> |Origin| ALB[AWS Application Load Balancer]
    ALB --> |Routes Traffic| ROSA[Red Hat OpenShift Service on AWS]
    
    subgraph AWS Cloud
        CloudFront
        WAF
        ALB
        subgraph ROSA Cluster
            ROSA
            subgraph Workloads
                API[API Services]
                Web[Web Applications]
                Microservices[Microservices]
            end
        end
    end
    
    classDef aws fill:#FF9900,stroke:#232F3E,color:white
    classDef rosa fill:#EE0000,stroke:#232F3E,color:white
    classDef network fill:#3F8624,stroke:#232F3E,color:white
    
    class CloudFront,WAF,ALB aws
    class ROSA,API,Web,Microservices rosa
    class Users network
```

### 2. ALB with WAF for ROSA Workloads

``` mermaid

flowchart LR
    Users((Internet Users)) --> ALB[AWS Application Load Balancer]
    WAF[AWS WAF] --> |Protects| ALB
    ALB --> |Routes Traffic| ROSA[Red Hat OpenShift Service on AWS]
    
    subgraph AWS Cloud
        WAF
        ALB
        subgraph ROSA Cluster
            ROSA
            subgraph Workloads
                API[API Services]
                Web[Web Applications]
                Microservices[Microservices]
            end
        end
    end
    
    classDef aws fill:#FF9900,stroke:#232F3E,color:white
    classDef rosa fill:#EE0000,stroke:#232F3E,color:white
    classDef network fill:#3F8624,stroke:#232F3E,color:white
    
    class ALB,WAF aws
    class ROSA,API,Web,Microservices rosa
    class Users network
```

### 3. AWS WAF Integrations with AWS Resources

``` mermaid


flowchart TD
    WAF[AWS WAF] --> CloudFront[Amazon CloudFront]
    WAF --> ALB[Application Load Balancer]
    WAF --> APIGW[Amazon API Gateway]
    WAF --> AppRunner[AWS App Runner]
    WAF --> Cognito[Amazon Cognito User Pool]
    WAF --> AppSync[AWS AppSync]
    
    subgraph External Access
        CloudFront --> |Origin| S3[Amazon S3]
        CloudFront --> |Origin| EC2[Amazon EC2]
        CloudFront --> |Origin| ECS[Amazon ECS]
        CloudFront --> |Origin| EKS[Amazon EKS]
        CloudFront --> |Origin| ROSA[Red Hat OpenShift]
        
        ALB --> EC2
        ALB --> ECS
        ALB --> EKS
        ALB --> ROSA
        
        APIGW --> Lambda[AWS Lambda]
        APIGW --> EC2
        APIGW --> ECS
        
        AppRunner
        Cognito
        AppSync
    end
    
    subgraph Internal Access
        PrivateLB[Internal ALB] --> PrivateEC2[Private EC2]
        PrivateLB --> PrivateECS[Private ECS]
        WAF --> PrivateLB
        
        PrivateAPIGW[Private API Gateway] --> PrivateLambda[Private Lambda]
        WAF --> PrivateAPIGW
    end
    
    classDef aws fill:#FF9900,stroke:#232F3E,color:white
    classDef security fill:#D13212,stroke:#232F3E,color:white
    classDef compute fill:#1EC9E1,stroke:#232F3E,color:white
    classDef storage fill:#3F8624,stroke:#232F3E,color:white
    
    class WAF security
    class CloudFront,ALB,APIGW,AppRunner,Cognito,AppSync,PrivateLB,PrivateAPIGW aws
    class EC2,ECS,EKS,ROSA,Lambda,PrivateEC2,PrivateECS,PrivateLambda compute
    class S3 storage
```

Application Load Balancer (ALB) with path-based routing rules

``` mermaid
flowchart LR
    Users((Internet Users)) --> WAF[AWS WAF]
    WAF --> ALB[Application Load Balancer]
    
    ALB -->|/api/*| APIService[API Service]
    ALB -->|/admin/*| AdminService[Admin Service]
    ALB -->|/static/*| StaticContent[Static Content]
    ALB -->|/* default| DefaultService[Default Service]
    
    subgraph "Security Layer"
        WAF
    end
    
    subgraph "Routing Layer"
        ALB
    end
    
    subgraph "Application Layer"
        APIService
        AdminService
        StaticContent
        DefaultService
    end
    
    classDef security fill:#D13212,stroke:#232F3E,color:white
    classDef routing fill:#FF9900,stroke:#232F3E,color:white
    classDef app fill:#1EC9E1,stroke:#232F3E,color:white
    
    class WAF security
    class ALB routing
    class APIService,AdminService,StaticContent,DefaultService app
```
AWS WAF with API Gateway Path-Based Routing
``` mermaid

flowchart LR
    Users((Internet Users)) --> WAF[AWS WAF]
    WAF --> APIGW[Amazon API Gateway]
    
    APIGW -->|/v1/users/*| UsersLambda[Users Lambda]
    APIGW -->|/v1/products/*| ProductsLambda[Products Lambda]
    APIGW -->|/v1/orders/*| OrdersLambda[Orders Lambda]
    APIGW -->|/admin/*| AdminService[Admin Service]
    
    subgraph "Security Rules"
        WAF -->|Rate limiting on /v1/* paths| RateLimit[Rate Limiting Rules]
        WAF -->|SQL injection protection on /v1/users/*| SQLi[SQL Injection Rules]
        WAF -->|IP restriction on /admin/*| IPRestrict[IP Restriction Rules]
    end
    
    classDef security fill:#D13212,stroke:#232F3E,color:white
    classDef routing fill:#FF9900,stroke:#232F3E,color:white
    classDef compute fill:#1EC9E1,stroke:#232F3E,color:white
    
    class WAF,RateLimit,SQLi,IPRestrict security
    class APIGW routing
    class UsersLambda,ProductsLambda,OrdersLambda,AdminService compute
```
AWS WAF with CloudFront Path-Based Routing

``` mermaid

flowchart LR
    Users((Internet Users)) --> WAF[AWS WAF]
    WAF --> CloudFront[Amazon CloudFront]
    
    CloudFront -->|/api/*| APIOrigin[API Origin]
    CloudFront -->|/static/*| S3Origin[S3 Static Content]
    CloudFront -->|/app/*| AppOrigin[Web App Origin]
    CloudFront -->|/* default| DefaultOrigin[Default Origin]
    
    subgraph "Security Layer"
        WAF -->|Bot control on all paths| BotControl[Bot Control Rules]
        WAF -->|XSS protection on /app/*| XSSProtect[XSS Protection Rules]
        WAF -->|Rate limiting on /api/*| APIRateLimit[API Rate Limiting]
    end
    
    subgraph "Origin Configuration"
        APIOrigin --> APIGateway[API Gateway]
        S3Origin --> S3Bucket[S3 Bucket]
        AppOrigin --> ALB[Application Load Balancer]
        DefaultOrigin --> EC2[EC2 Instance]
        
        APIGateway -->|Internal routing| Lambdas[Lambda Functions]
        ALB -->|Internal routing| Containers[Container Services]
    end
    
    classDef security fill:#D13212,stroke:#232F3E,color:white
    classDef cdn fill:#FF9900,stroke:#232F3E,color:white
    classDef compute fill:#1EC9E1,stroke:#232F3E,color:white
    classDef storage fill:#3F8624,stroke:#232F3E,color:white
    
    class WAF,BotControl,XSSProtect,APIRateLimit security
    class CloudFront cdn
    class APIGateway,ALB,EC2,Lambdas,Containers compute
    class S3Bucket storage
```

``` mermaid

flowchart TD
    Users((Internet Users)) --> WAF[AWS WAF]
    WAF --> ALB[Application Load Balancer]
    
    subgraph "Security Layer"
        WAF -->|SQL Injection Protection| SQLi[SQL Injection Rules]
        WAF -->|XSS Protection| XSS[XSS Protection Rules]
        WAF -->|Rate Limiting| RateLimit[Rate Limiting Rules]
        WAF -->|Bot Control| BotControl[Bot Control Rules]
        WAF -->|Geo Restrictions| GeoBlock[Geographic Restrictions]
        WAF -->|IP Reputation| IPRep[IP Reputation Lists]
    end
    
    ALB -->|/api/v1/*| APIRoutes[API Routes]
    ALB -->|/app/*| WebAppRoutes[Web App Routes]
    ALB -->|/admin/*| AdminRoutes[Admin Routes]
    ALB -->|/auth/*| AuthRoutes[Auth Routes]
    ALB -->|/static/*| StaticRoutes[Static Content Routes]
    ALB -->|/metrics/*| MetricsRoutes[Metrics Routes]
    
    subgraph "ROSA Cluster"
        APIRoutes --> APIServices[API Microservices]
        WebAppRoutes --> WebFrontends[Web Frontends]
        AdminRoutes --> AdminPortals[Admin Portals]
        AuthRoutes --> AuthServices[Authentication Services]
        StaticRoutes --> StaticContent[Static Content Servers]
        MetricsRoutes --> Monitoring[Monitoring Services]
        
        subgraph "API Workloads"
            APIServices --> |REST| RESTAPIs[REST APIs]
            APIServices --> |GraphQL| GraphQLAPIs[GraphQL APIs]
            APIServices --> |gRPC| GRPCAPIs[gRPC Services]
        end
        
        subgraph "Web Workloads"
            WebFrontends --> CustomerPortal[Customer Portal]
            WebFrontends --> PublicWebsite[Public Website]
            WebFrontends --> MobileBackend[Mobile App Backend]
        end
        
        subgraph "Admin Workloads"
            AdminPortals --> InternalDashboard[Internal Dashboard]
            AdminPortals --> ConfigManagement[Configuration Management]
            AdminPortals --> UserManagement[User Management]
        end
        
        subgraph "Auth Workloads"
            AuthServices --> OAuth[OAuth Provider]
            AuthServices --> SAML[SAML Integration]
            AuthServices --> MFA[MFA Services]
        end
        
        subgraph "Static Workloads"
            StaticContent --> Images[Image Assets]
            StaticContent --> Documents[Document Assets]
            StaticContent --> Downloads[Downloads]
        end
        
        subgraph "Monitoring Workloads"
            Monitoring --> Prometheus[Prometheus]
            Monitoring --> Grafana[Grafana]
            Monitoring --> Jaeger[Jaeger Tracing]
        end
    end
    
    classDef security fill:#D13212,stroke:#232F3E,color:white
    classDef routing fill:#FF9900,stroke:#232F3E,color:white
    classDef rosa fill:#EE0000,stroke:#232F3E,color:white
    classDef api fill:#1EC9E1,stroke:#232F3E,color:white
    classDef web fill:#3F8624,stroke:#232F3E,color:white
    classDef admin fill:#8C4FFF,stroke:#232F3E,color:white
    classDef auth fill:#FF9D00,stroke:#232F3E,color:white
    classDef static fill:#7AA116,stroke:#232F3E,color:white
    classDef monitoring fill:#527FFF,stroke:#232F3E,color:white
    
    class WAF,SQLi,XSS,RateLimit,BotControl,GeoBlock,IPRep security
    class ALB,APIRoutes,WebAppRoutes,AdminRoutes,AuthRoutes,StaticRoutes,MetricsRoutes routing
    class ROSA rosa
    class APIServices,RESTAPIs,GraphQLAPIs,GRPCAPIs api
    class WebFrontends,CustomerPortal,PublicWebsite,MobileBackend web
    class AdminPortals,InternalDashboard,ConfigManagement,UserManagement admin
    class AuthServices,OAuth,SAML,MFA auth
    class StaticContent,Images,Documents,Downloads static
    class Monitoring,Prometheus,Grafana,Jaeger monitoring
```

``` mermaid

flowchart LR
    Users((Users)) --> WAF[WAF]
    WAF --> ALB[ALB]
    
    subgraph "Security"
        WAF --> SQLi[SQLi]
        WAF --> XSS[XSS]
        WAF --> Rate[Rate Limit]
        WAF --> Bot[Bot Control]
        WAF --> Geo[Geo Block]
        WAF --> IP[IP Rep]
        WAF --> Admin[Admin Protection]
    end
    
    ALB -->|/api| API[API]
    ALB -->|/app| Web[Web]
    ALB -->|/admin| Adm[Admin]
    ALB -->|/auth| Auth[Auth]
    ALB -->|/static| Static[Static]
    ALB -->|/metrics| Metrics[Metrics]
    
    subgraph "ROSA"
        API --> REST & GraphQL & gRPC
        Web --> Portal & Website & Mobile
        Adm --> Dashboard & Config & Users
        Auth --> OAuth & SAML & MFA
        Static --> Images & Docs
        Metrics --> Prometheus & Grafana
    end
    
    classDef security fill:#D13212,stroke:#232F3E,color:white
    classDef routing fill:#FF9900,stroke:#232F3E,color:white
    classDef rosa fill:#EE0000,stroke:#232F3E,color:white
    
    class WAF,SQLi,XSS,Rate,Bot,Geo,IP,Admin security
    class ALB,API,Web,Adm,Auth,Static,Metrics routing
    class REST,GraphQL,gRPC,Portal,Website,Mobile,Dashboard,Config,Users,OAuth,SAML,MFA,Images,Docs,Prometheus,Grafana rosa
```
##### For path-based routing or forwarding based on URL prefixes, you would need to use:

    Application Load Balancer (ALB) with path-based routing rules

    Amazon API Gateway with path-based routing

    Amazon CloudFront with origin path patterns


##### Common Security Attacks on Externally Exposed ROSA Workloads

##### Application Layer Attacks
SQL Injection: Attackers insert malicious SQL code into application inputs

Cross-Site Scripting (XSS): Injecting client-side scripts into web pages viewed by others

Cross-Site Request Forgery (CSRF): Forcing users to execute unwanted actions

Command Injection: Executing arbitrary commands on the host operating system

Insecure Deserialization: Exploiting flaws in object serialization/deserialization

##### API Security Threats
API Abuse: Excessive API calls causing resource exhaustion

Broken Authentication: Exploiting weak authentication mechanisms

Broken Authorization: Accessing resources without proper permissions

Improper Asset Management: Attacking undocumented or unprotected API endpoints

Insufficient Logging: Attacks going undetected due to poor monitoring

##### Infrastructure Attacks

DDoS Attacks: Overwhelming services with traffic

Container Escape: Breaking out of container isolation

Kubernetes API Server Attacks: Unauthorized access to the control plane

Credential Theft: Stealing service account tokens or credentials

Privilege Escalation: Gaining higher permissions than intended

##### Network-Level Attacks
Man-in-the-Middle: Intercepting and potentially altering communications

Port Scanning: Discovering open ports and services

DNS Poisoning: Redirecting traffic to malicious endpoints

TLS Vulnerabilities: Exploiting weaknesses in encryption

##### Other Common Threats

Brute Force Attacks: Attempting to guess credentials

Credential Stuffing: Using leaked credentials from other breaches

Bots and Scrapers: Automated tools that consume resources or steal data

Supply Chain Attacks: Compromising dependencies or container images

Zero-Day Exploits: Attacks using previously unknown vulnerabilities
