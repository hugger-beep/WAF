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
For path-based routing or forwarding based on URL prefixes, you would need to use:

Application Load Balancer (ALB) with path-based routing rules

Amazon API Gateway with path-based routing

Amazon CloudFront with origin path patterns
