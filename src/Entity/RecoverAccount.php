<?php

namespace App\Entity;

use App\Repository\RecoverAccountRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: RecoverAccountRepository::class)]
class RecoverAccount
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $recoveryToken = null;

    #[ORM\Column(length: 255)]
    private ?string $email = null;

    #[ORM\Column]
    private ?int $date = null;

    #[ORM\Column]
    private ?bool $used = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getRecoveryToken(): ?string
    {
        return $this->recoveryToken;
    }

    public function setRecoveryToken(string $recoveryToken): self
    {
        $this->recoveryToken = $recoveryToken;

        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function getDate(): ?int
    {
        return $this->date;
    }

    public function setDate(int $date): self
    {
        $this->date = $date;

        return $this;
    }

    public function isUsed(): ?bool
    {
        return $this->used;
    }

    public function setUsed(bool $used): self
    {
        $this->used = $used;

        return $this;
    }
}
