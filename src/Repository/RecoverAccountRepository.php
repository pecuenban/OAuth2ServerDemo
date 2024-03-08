<?php

namespace App\Repository;

use App\Entity\RecoverAccount;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<RecoverAccount>
 *
 * @method RecoverAccount|null find($id, $lockMode = null, $lockVersion = null)
 * @method RecoverAccount|null findOneBy(array $criteria, array $orderBy = null)
 * @method RecoverAccount[]    findAll()
 * @method RecoverAccount[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class RecoverAccountRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, RecoverAccount::class);
    }

    public function save(RecoverAccount $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(RecoverAccount $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function getRecoverData($email)
    {
        $recover_url = "https://cerebro.test-quasardynamics.company/recover-new-password?token=";
        $passphrase = "t%~B^g%Q~Q]2Aw6S%V;R2DJnXj*Xcm2{#3y6+\^-Ts~:K*Kq^g5!Pj.~6F~R.>m#";
        $length = openssl_cipher_iv_length("AES-256-CBC");
        $iv = openssl_random_pseudo_bytes($length);
        $time = time() + 24 * 60 * 60;
        $plainText = $email . "___" . $time;
        $encrypted = openssl_encrypt($plainText, "AES-256-CBC", $passphrase, OPENSSL_RAW_DATA, $iv);
        $token = base64_encode($encrypted). '|' . base64_encode($iv);
        $url = $recover_url . $token;

        return [$url, $time, $token];
    }
}
