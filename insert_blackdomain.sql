-- Inserir/Atualizar máquina BlackDomain com descrições em PT e EN
INSERT INTO public.challenges (
    id,
    name,
    type,
    category,
    difficulty,
    description,
    description_pt,
    estimated_time,
    points,
    image_id,
    config,
    is_active
) VALUES (
    'blackdomain',
    'BlackDomain',
    'vm',
    'active_directory',
    'hard',
    'A corporate-style environment with several machines working under a shared domain. Careful enumeration and strategic exploitation are required to progress through the environment and reach the highest level of access.',
    'Um ambiente estilo corporativo com várias máquinas operando sob um domínio compartilhado. Enumeração cuidadosa e exploração estratégica são necessárias para progredir no ambiente e alcançar o nível mais alto de acesso.',
    '4-6 hours',
    100,
    'blackdomain',
    '{
        "id": "blackdomain",
        "name": "BlackDomain",
        "type": "vm",
        "category": "active_directory",
        "difficulty": "hard",
        "estimated_time": "4-6 hours",
        "image_build_path": "labs/Network/BlackDomain",
        "skillsRequired": "Active Directory, Enumeração, Windows",
        "attackSurface": "Internal Network",
        "flags": {
            "user": "XACK{c4ca4238a0b923820dcc509a6f75849b}",
            "root": "XACK{eccbc87e4b5ce2fe28308fd9f2a7baf3}"
        },
        "hints": [
            "Enumere portas padrão (445, 88, 389). Nem tudo precisa de credenciais.",
            "Verifique compartilhamentos SMB públicos em busca de informações.",
            "Usuários antigos podem ter configurações inseguras (AS-REP Roasting).",
            "Políticas de grupo (GPO) antigas podem conter segredos."
        ],
        "learning_objectives": [
            "Enumeração de Active Directory",
            "Exploração de SMB e RPC",
            "Ataques Kerberos (Kerberoasting, AS-REP)",
            "Escalação de Privilégios (GPP, SeBackupPrivilege)"
        ]
    }'::jsonb,
    true
) ON CONFLICT (id) DO UPDATE SET
    description = EXCLUDED.description,
    description_pt = EXCLUDED.description_pt,
    config = EXCLUDED.config,
    points = EXCLUDED.points,
    type = EXCLUDED.type,
    category = EXCLUDED.category;
