<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20231129080138 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE oauth2_access_token CHANGE user_identifier user_identifier VARCHAR(128) DEFAULT NULL');
        $this->addSql('ALTER TABLE oauth2_authorization_code CHANGE user_identifier user_identifier VARCHAR(128) DEFAULT NULL');
        $this->addSql('ALTER TABLE oauth2_client CHANGE secret secret VARCHAR(128) DEFAULT NULL');
        $this->addSql('ALTER TABLE oauth2_refresh_token CHANGE access_token access_token CHAR(80) DEFAULT NULL');
        $this->addSql('ALTER TABLE oauth2_user_consent CHANGE expires expires DATETIME DEFAULT NULL COMMENT \'(DC2Type:datetime_immutable)\', CHANGE scopes scopes LONGTEXT DEFAULT NULL COMMENT \'(DC2Type:simple_array)\', CHANGE ip_address ip_address VARCHAR(255) DEFAULT NULL');
        $this->addSql('ALTER TABLE user ADD name VARCHAR(255) NOT NULL, ADD surname VARCHAR(255) NOT NULL, CHANGE roles roles JSON NOT NULL');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE oauth2_access_token CHANGE user_identifier user_identifier VARCHAR(128) DEFAULT \'NULL\'');
        $this->addSql('ALTER TABLE oauth2_authorization_code CHANGE user_identifier user_identifier VARCHAR(128) DEFAULT \'NULL\'');
        $this->addSql('ALTER TABLE oauth2_client CHANGE secret secret VARCHAR(128) DEFAULT \'NULL\'');
        $this->addSql('ALTER TABLE oauth2_refresh_token CHANGE access_token access_token CHAR(80) DEFAULT \'NULL\'');
        $this->addSql('ALTER TABLE oauth2_user_consent CHANGE expires expires DATETIME DEFAULT \'NULL\' COMMENT \'(DC2Type:datetime_immutable)\', CHANGE scopes scopes LONGTEXT DEFAULT \'NULL\' COMMENT \'(DC2Type:simple_array)\', CHANGE ip_address ip_address VARCHAR(255) DEFAULT \'NULL\'');
        $this->addSql('ALTER TABLE user DROP name, DROP surname, CHANGE roles roles LONGTEXT NOT NULL COLLATE `utf8mb4_bin`');
    }
}
