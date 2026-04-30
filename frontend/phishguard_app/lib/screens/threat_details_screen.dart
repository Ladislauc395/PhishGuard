import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../models/analyze_response.dart';

class ThreatDetailsScreen extends StatelessWidget {
  final AnalyzeResponse result;
  const ThreatDetailsScreen({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    final unsafe = result.isUnsafe;
    final color = unsafe ? AppColors.danger : AppColors.success;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Threat Details'),
        centerTitle: true,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Banner de Status (Risco Alto ou Seguro)
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: color.withOpacity(0.08),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(children: [
              Icon(unsafe ? Icons.warning : Icons.check_circle,
                  color: color, size: 32),
              const SizedBox(width: 12),
              Expanded(
                  child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(unsafe ? 'High Risk Threat' : 'Safe',
                      style: TextStyle(
                          color: color,
                          fontWeight: FontWeight.bold,
                          fontSize: 18)),
                  Text('Detected ${result.timestamp.toLocal()}',
                      style: const TextStyle(
                          color: AppColors.textMuted, fontSize: 12)),
                ],
              )),
            ]),
          ),

          const SizedBox(height: 20),

          // Detalhes Técnicos Básicos
          _row('Score', '${result.score}/100'),
          _row('Verdict', result.verdict),
          _row('Analysis ID', result.analysisId?.toString() ?? 'N/A'),

          // --- ADIÇÃO: Bloco de Análise IA (Groq) ---
          if (result.ml != null) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.primary.withOpacity(0.08),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(children: [
                    const Icon(Icons.psychology,
                        color: AppColors.primary, size: 20),
                    const SizedBox(width: 8),
                    const Text('Análise IA (Groq)',
                        style: TextStyle(
                            fontWeight: FontWeight.w600,
                            color: AppColors.primary)),
                    const Spacer(),
                    Text('${result.mlScore ?? 0}/100',
                        style: const TextStyle(fontWeight: FontWeight.bold)),
                  ]),
                  const SizedBox(height: 6),
                  Text(
                      result.mlReasoning ??
                          'Sem explicação detalhada disponível.',
                      style: const TextStyle(fontSize: 13, height: 1.4)),
                  if (result.keywordsFound.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    const Text('Termos Suspeitos:',
                        style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            color: AppColors.textMuted)),
                    const SizedBox(height: 4),
                    Wrap(
                        spacing: 6,
                        runSpacing:
                            -8, // Ajuste para chips não ficarem muito afastados
                        children: result.keywordsFound
                            .map((k) => Chip(
                                  label: Text(k,
                                      style: const TextStyle(fontSize: 11)),
                                  backgroundColor:
                                      AppColors.warning.withOpacity(0.2),
                                  visualDensity: VisualDensity.compact,
                                ))
                            .toList()),
                  ],
                ],
              ),
            ),
          ],
          // --- FIM DA ADIÇÃO ---

          const SizedBox(height: 20),

          // Seção de Motivos Detetados (Regras Heurísticas)
          const Text('Why is this dangerous?',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
          const SizedBox(height: 8),

          if (result.reasons.isEmpty)
            const Text('No specific heuristic reasons identified.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 14))
          else
            ...result.reasons.map((r) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                          width: 8,
                          height: 8,
                          margin: const EdgeInsets.only(top: 6, right: 8),
                          decoration: BoxDecoration(
                              color: color, shape: BoxShape.circle)),
                      Expanded(
                          child: Text(r, style: const TextStyle(fontSize: 14))),
                    ]))),

          const SizedBox(height: 32),

          // Botões de Ação
          Row(children: [
            Expanded(
                child: ElevatedButton(
                    onPressed: () {
                      // Lógica para bloquear/remover
                    },
                    style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.danger,
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 12)),
                    child: const Text('Block'))),
            const SizedBox(width: 8),
            Expanded(
                child: OutlinedButton(
                    onPressed: () {}, child: const Text('Report'))),
            const SizedBox(width: 8),
            Expanded(
                child: OutlinedButton(
                    onPressed: () {}, child: const Text('Mark Safe'))),
          ]),
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  // Widget auxiliar para as linhas de informação
  Widget _row(String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child:
            Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Text(k, style: const TextStyle(color: AppColors.textMuted)),
          Flexible(
              child: Text(v,
                  style: const TextStyle(fontWeight: FontWeight.w600),
                  textAlign: TextAlign.right)),
        ]),
      );
}
