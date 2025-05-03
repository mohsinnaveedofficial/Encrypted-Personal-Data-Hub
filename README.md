![Screenshot 2025-05-02 221305](https://github.com/user-attachments/assets/64d05efa-4349-4d2b-8231-a3c014e3faa6)
![Screenshot 2025-05-02 221252](https://github.com/user-attachments/assets/3544b49b-c946-45c2-b782-df2432937531)
![Screenshot 2025-05-02 221345](https://github.com/user-attachments/assets/7ef9f6fb-98a3-4a5d-8b77-3958da9b0a38)
![Screenshot 2025-05-01 215517](https://github.com/user-attachments/assets/81cb74ad-d163-4dfb-9502-c041310dcf1c)

The Secure Personal Data H is a secure plaubtform that allows users to store their personal data in encrypted form, ensuring that even the server  and database owner cannot access the content. Users can selectively share encrypted data with specific individuals who have accounts in the system. Unshared data can be deleted permanently by the user.
The system focuses on privacy, control, and secure sharing by using client-side encryption, access-controlled sharing, and a relational database to manage data and user interactions. It ensures that users remain the sole owners of their data, supporting features like end-to-end encryption
Features
🔒 Full data privacy: All user data is encrypted and inaccessible to the backend system.

👤 Selective sharing: Users can share encrypted data with others who have accounts.

🧹 User-controlled deletion: Any data not shared can be permanently deleted by the user.

📁 Relational data model: Efficiently organizes and links encrypted user data and access permissions.

Technologies Used
Frontend: JavaScript,html and bootstrap

Backend: Node.js / Express 

Database: MySQL 

Encryption: AES / RSA 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Before starting the backend server, you must create the required tables and stored procedures or function in your database. and setup the connection 

DDL Queries:

    create database decentralized_db;
    use decentralized_db;

    CREATE TABLE Users (
    user_id         INT PRIMARY KEY identity(1,1),
    name        VARCHAR(100) UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    public_key      TEXT NOT NULL,
    private_key_enc TEXT NOT NULL,
    created_at      Datetime DEFAULT GETDATE()
    );

    create table UserData(
    data_id int primary key identity(1,1),
    user_id int ,
    data_type_id int ,
    encrypted_data text not null,
    iv TEXT NOT NULL,
    created_at Datetime default getdate(),
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (data_type_id) REFERENCES DataTypes(data_id)
    )


    create table Encryption_Keys(
    key_user_id int primary key identity(1,1),
    user_id int not null,
    data_id int not null,
    key_enc   TEXT NOT NULL,
    created_at Datetime default getdate(),
    foreign key (user_id) references  db_owner.Users(user_id),
    foreign key (data_id) references db_owner.UserData(data_id)
    )

    create table UserProfile(
    profile_id int primary key identity(1,1),
    user_id int references db_owner.Users(user_id) ,
    fullname varchar(100),
    email varchar(100),
    phone_number int ,
    created_at  datetime default getdate()
    )


    create table DataTypes(
    data_id int primary Key identity(1,1),
    type_name varchar(50) unique not null,
    decription varchar(100)
    );

    create table SharedData (
    shared_id int primary key identity(1,1),
    sender_id nvarchar(255) NOT NULL,
    receiver_id nvarchar(255) NOT NULL,
    encrypted_data nvarchar(MAX) NOT NULL,
    key_enc nvarchar(MAX) NOT NULL,
    iv nvarchar(255) NOT NULL,
    created_at datetime default GETDATE()
    );




DML Queries 



    insert into DataTypes(type_name,decription)
    values
    ('Medical', 'Medical records and health data'),
    ('Financial', 'Bank details, transactions, assets'),
    ('PersonalID', 'Passport, ID card, driver’s license'),
    ('Education', 'Certificates, degrees, transcripts'),
    ('Employment', 'Job records, resumes, contracts'),
    ('Credentials', 'Usernames, passwords, 2FA tokens'),
    ('Legal', 'Contracts, legal documents, agreements'),
    ('Property', 'Land deeds, ownership proofs');


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

   Function:

    create function getDataById(@user_id int)
    returns table
    as 
    return (select *
        from  db_owner.UserData
         join Encryption_Keys 
        on UserData.data_id=Encryption_Keys.data_id
         join 
        db_owner.DataTypes
        on DataTypes.data_id=UserData.data_type_id  
        where UserData.user_id=@user_id)



Store Procedure:
     
    create procedure delete_data 
    @data_id int 
    as 
    begin 
    delete from Encryption_Keys where data_id=@data_id
    delete from db_owner.UserData where data_id=@data_id
    end


