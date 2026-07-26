// dns-authority-transition
//
// Binário chamado por um script wrapper registrado em
// /etc/NetworkManager/dispatcher.d/, disparado a cada evento de rede.
//
// Responsabilidade única: quando a interface da sua VPN sobe, aponta
// /etc/resolv.conf para o DNS interno fornecido por ela (lido do ambiente
// que o próprio NetworkManager já disponibiliza ao dispatcher). Quando a
// interface desce, reverte para o resolvedor local de sua preferência
// (AdGuard Home, Pi-hole, Unbound, ou qualquer outro).
//
// ============================================================================
// AJUSTE NECESSÁRIO ANTES DE USAR — leia o README.md primeiro
// ============================================================================
// As duas constantes abaixo (VPN_INTERFACE e FALLBACK_DNS) são específicas
// do SEU ambiente e quase certamente precisam ser alteradas. Este projeto
// foi desenvolvido e testado contra um cliente VPN específico no autor's
// próprio sistema Arch Linux; ele NÃO detecta automaticamente qual VPN
// você usa, nem qual é o nome real da interface dela.
//
// Para descobrir os valores corretos para o seu caso, veja a seção
// "Descobrindo os valores para sua VPN" no README.md — o processo envolve
// um script de dispatcher temporário, só de leitura, que registra em log
// o nome da interface e as variáveis de ambiente reais que o
// NetworkManager expõe quando sua VPN conecta/desconecta.
// ============================================================================

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::ExitCode;
use std::str::FromStr;

/// Flag de imutabilidade do inode, mesma usada por chattr(1)/lsattr(1).
/// Valor fixo pela UAPI do kernel (include/uapi/linux/fs.h), estável entre
/// versões e filesystems (ext4, btrfs, f2fs).
const FS_IMMUTABLE_FL: libc::c_int = 0x00000010;

/// Números de ioctl para GETFLAGS/SETFLAGS de atributos de inode, mesma
/// UAPI usada por ext4, btrfs, f2fs, etc.
const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
const FS_IOC_SETFLAGS: libc::c_ulong = 0x40086602;

/// Caminho alvo único que este binário tem permissão de tocar.
/// Fixo em tempo de compilação: não vem de argumento, não vem de env,
/// para eliminar qualquer possibilidade de path injection.
const RESOLV_CONF: &str = "/etc/resolv.conf";

// ============================================================================
// >>> AJUSTE AQUI (1/2): seu resolvedor DNS local de repouso <<<
// Substitua pelo IP do seu AdGuard Home, Pi-hole, Unbound, ou outro
// resolvedor local — o DNS que deve estar ativo quando a VPN NÃO está
// conectada.
// ============================================================================
const FALLBACK_DNS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

// ============================================================================
// >>> AJUSTE AQUI (2/2): o nome real da interface da sua VPN <<<
// Descubra o valor correto seguindo o README.md antes de compilar.
// Não existe fallback silencioso para "qualquer interface WireGuard" —
// isso é deliberado, para que o binário nunca reaja a uma interface que
// você não revisou e confirmou manualmente.
// ============================================================================
const VPN_INTERFACE: &str = "SUBSTITUA_PELO_NOME_DA_SUA_INTERFACE";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dns-authority-transition: abortando sem escrever, motivo: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    // ---- 1. Sandbox Landlock: aplicado ANTES de qualquer lógica de negócio ----
    apply_landlock_sandbox()?;

    // ---- 2. Ler e validar argumentos posicionais ----
    let args: Vec<String> = env::args().collect();
    let interface = args.get(1).ok_or("argumento 1 (interface) ausente")?;
    let action = args.get(2).ok_or("argumento 2 (action) ausente")?;

    if interface != VPN_INTERFACE {
        return Ok(());
    }

    let new_dns: Ipv4Addr = match action.as_str() {
        "up" => read_vpn_dns_from_env()?,
        "down" => FALLBACK_DNS,
        _ => return Ok(()),
    };

    // ---- 3. Abrir a janela: remover imutabilidade ----
    set_immutable(false)?;

    // ---- 4. Escrita atômica: nunca edição in-place ----
    let write_result = write_resolv_conf_atomic(new_dns);

    // ---- 5. Fechar a janela: reaplicar imutabilidade, sempre ----
    let lock_result = set_immutable(true);

    write_result?;
    lock_result?;

    Ok(())
}

/// Restringe este processo, via Landlock, a só poder abrir caminhos dentro
/// de /etc em modo leitura/escrita/criação/remoção de arquivo regular.
fn apply_landlock_sandbox() -> Result<(), String> {
    let abi = ABI::V5;

    let resolv_dir_fd = PathFd::new("/etc")
        .map_err(|e| format!("não foi possível abrir /etc para sandbox: {e}"))?;

    // Acesso concedido dentro de /etc, restrito ao mínimo necessário para o
    // padrão write-then-rename atômico:
    //   - MakeReg:    criar o arquivo temporário (.tmp)
    //   - WriteFile:  escrever conteúdo nele
    //   - ReadFile:   permite reabrir o arquivo para ioctl de flags
    //   - RemoveFile: rename() exige direito de remoção sobre a ORIGEM,
    //                 mesmo movendo dentro do mesmo diretório.
    let etc_access =
        AccessFs::WriteFile | AccessFs::ReadFile | AccessFs::MakeReg | AccessFs::RemoveFile;

    let restriction = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("falha ao configurar ruleset Landlock: {e}"))?
        .create()
        .map_err(|e| format!("falha ao criar ruleset Landlock: {e}"))?
        .add_rule(PathBeneath::new(resolv_dir_fd, etc_access))
        .map_err(|e| format!("falha ao adicionar regra Landlock: {e}"))?
        .restrict_self()
        .map_err(|e| format!("falha ao aplicar sandbox Landlock: {e}"))?;

    if restriction.ruleset == RulesetStatus::NotEnforced {
        return Err(
            "kernel não suporta/aplicou Landlock — abortando por segurança \
             (fail-closed: recusamos rodar sem sandbox)"
                .to_string(),
        );
    }

    Ok(())
}

/// Lê o DNS interno da VPN a partir da variável de ambiente que o próprio
/// NetworkManager já injeta no dispatcher no momento do evento "up".
fn read_vpn_dns_from_env() -> Result<Ipv4Addr, String> {
    let raw = env::var("IP4_NAMESERVERS")
        .map_err(|_| "IP4_NAMESERVERS ausente do ambiente no evento 'up'".to_string())?;

    let first = raw
        .split_whitespace()
        .next()
        .ok_or("IP4_NAMESERVERS vazio")?;

    let ip = Ipv4Addr::from_str(first)
        .map_err(|e| format!("IP4_NAMESERVERS não é um IPv4 válido ({first}): {e}"))?;

    if ip.is_unspecified() {
        return Err(format!(
            "IP4_NAMESERVERS resolveu para endereço não especificado ({ip}), recusando"
        ));
    }

    Ok(ip)
}

/// Liga (immutable=true) ou desliga (immutable=false) o atributo FS_IMMUTABLE_FL
/// em RESOLV_CONF via ioctl direto, equivalente a `chattr +i` / `chattr -i`.
/// Requer CAP_LINUX_IMMUTABLE, que o processo já possui por rodar como root.
fn set_immutable(immutable: bool) -> Result<(), String> {
    if !Path::new(RESOLV_CONF).exists() {
        return Ok(());
    }

    let file = OpenOptions::new()
        .read(true)
        .open(RESOLV_CONF)
        .map_err(|e| format!("falha ao abrir {RESOLV_CONF} para ajustar atributo: {e}"))?;

    let fd = file.as_raw_fd();
    let mut flags: libc::c_int = 0;

    // SAFETY: fd é válido (obtido de File aberto com sucesso acima) e
    // aponta para uma flags: c_int local, com o tamanho esperado pela
    // syscall FS_IOC_GETFLAGS/SETFLAGS para esta plataforma.
    let get_result = unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags as *mut libc::c_int) };
    if get_result != 0 {
        return Err(format!(
            "ioctl FS_IOC_GETFLAGS falhou: {}",
            std::io::Error::last_os_error()
        ));
    }

    if immutable {
        flags |= FS_IMMUTABLE_FL;
    } else {
        flags &= !FS_IMMUTABLE_FL;
    }

    // SAFETY: mesma justificativa acima, para a operação de escrita das flags.
    let set_result = unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS, &flags as *const libc::c_int) };
    if set_result != 0 {
        return Err(format!(
            "ioctl FS_IOC_SETFLAGS falhou: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Escreve o novo resolv.conf via padrão write-then-rename: nunca há um
/// instante em que o arquivo existe em estado parcialmente escrito.
fn write_resolv_conf_atomic(dns: Ipv4Addr) -> Result<(), String> {
    let target = Path::new(RESOLV_CONF);
    let dir = target
        .parent()
        .ok_or("RESOLV_CONF não tem diretório pai")?;
    let tmp_path = dir.join(".resolv.conf.dns-authority-transition.tmp");

    let contents = format!(
        "# Gerenciado por dns-authority-transition — não editar manualmente\n\
         nameserver {dns}\n"
    );

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp_path)
            .map_err(|e| format!("falha ao criar arquivo temporário: {e}"))?;

        f.write_all(contents.as_bytes())
            .map_err(|e| format!("falha ao escrever arquivo temporário: {e}"))?;

        f.sync_all()
            .map_err(|e| format!("falha ao sincronizar arquivo temporário para disco: {e}"))?;
    }

    fs::rename(&tmp_path, target)
        .map_err(|e| format!("falha ao renomear atomicamente para {RESOLV_CONF}: {e}"))?;

    Ok(())
}
